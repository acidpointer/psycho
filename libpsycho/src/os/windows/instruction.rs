//! Simplified instruction analysis and trampoline generation

use std::ffi::c_void;
use thiserror::Error;
use log::{debug, info, error, trace};

use iced_x86::{
    Decoder, DecoderOptions, Instruction, Mnemonic,
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

#[derive(Debug)]
pub struct PrologAnalysis {
    pub original_bytes: Vec<u8>,
    pub patch_size: usize,
}

pub struct ArchConstants {
    pub pointer_size: usize,
    pub jump_instruction_size: usize,
    pub min_hook_size: usize,
}

impl ArchConstants {
    pub fn current() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self {
                pointer_size: 8,
                jump_instruction_size: 5, // Prefer 5-byte relative jump, fallback to 12-byte absolute
                min_hook_size: 5,
            }
        }
        #[cfg(target_arch = "x86")]
        {
            Self {
                pointer_size: 4,
                jump_instruction_size: 5,
                min_hook_size: 5,
            }
        }
    }
}

pub fn analyze_function_prolog(
    function_address: *const c_void,
    min_bytes: usize,
) -> InstructionResult<PrologAnalysis> {
    debug!("Analyzing function prolog at {:p}, min_bytes={}", function_address, min_bytes);

    let arch = ArchConstants::current();
    let required_bytes = min_bytes.max(arch.min_hook_size);
    let analysis_size = required_bytes.max(64); // Read more bytes to find padding

    trace!("Reading {} bytes from {:p} for analysis", analysis_size, function_address);
    let bytes = read_bytes(function_address, analysis_size)?;

    debug!("Read {} bytes: {:02x?}", bytes.len(),
           if bytes.len() <= 16 { bytes.as_slice() } else { &bytes[..16] });

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

    let mut total_length = 0usize;
    let mut found_problematic = false;
    let mut problematic_offset = 0usize;

    // First pass: analyze instructions and find problematic ones
    while total_length < analysis_size && total_length < 100 {
        let instruction = decoder.decode();

        if instruction.is_invalid() {
            break; // Stop at invalid instructions - might be padding or end of function
        }

        trace!("Decoded instruction: {:?} at offset {}, len={}",
               instruction.mnemonic(), total_length, instruction.len());

        if is_problematic_instruction(&instruction) && !found_problematic {
            found_problematic = true;
            problematic_offset = total_length;
            debug!("Found problematic instruction {:?} at offset {}",
                   instruction.mnemonic(), total_length);
        }

        total_length += instruction.len();
    }

    // Smart decision making for patch size
    let patch_size = if found_problematic {
        if problematic_offset >= required_bytes {
            // We have enough safe bytes before the problematic instruction
            problematic_offset
        } else {
            // For small functions with problematic instructions at the boundary,
            // we can still hook if we have at least 5 bytes before the problematic instruction
            if problematic_offset >= 5 {
                debug!("Small function detected: using {} bytes (problematic instruction at {})",
                       problematic_offset, problematic_offset);
                problematic_offset
            } else {
                error!("Function too small for any JMP hook: found problematic instruction at offset {}, need at least 5 bytes",
                       problematic_offset);
                return Err(InstructionError::UnsafeHookLocation(
                    format!("Function too small: found problematic instruction at offset {}, need at least 5 bytes for relative jump (use IAT or VMT hooking instead)",
                           problematic_offset)
                ));
            }
        }
    } else {
        // No problematic instructions found, use minimum required
        required_bytes.min(total_length)
    };

    if patch_size < required_bytes {
        error!("Insufficient bytes for safe hooking: got {} bytes, needed {}",
               patch_size, required_bytes);
        return Err(InstructionError::InsufficientBytes(required_bytes));
    }

    // For trampoline, we need to be smart about what instructions we copy
    let trampoline_bytes_count = if found_problematic && problematic_offset > 0 {
        // For functions ending with RET, we need to copy everything INCLUDING the RET
        // because that's the complete function behavior
        if problematic_offset < required_bytes {
            // We found RET before we have enough bytes - this is a complete small function
            // We'll handle this in trampoline generation by not adding a return jump
            problematic_offset + 1 // Include the RET instruction
        } else {
            problematic_offset
        }
    } else {
        // Copy minimum required bytes for clean instructions
        required_bytes.min(total_length)
    };

    let original_bytes = bytes[..trampoline_bytes_count].to_vec();
    info!("Prolog analysis complete: patch_size={} bytes, trampoline_bytes={} bytes",
          patch_size, trampoline_bytes_count);

    Ok(PrologAnalysis {
        original_bytes,
        patch_size,
    })
}

/// Find a safe patch zone by looking for padding bytes (NOPs, INT3, etc.)
/// Also ensures we don't overwrite other functions
fn find_safe_patch_zone(bytes: &[u8], required_bytes: usize) -> InstructionResult<usize> {
    // Look for common padding patterns that we can safely overwrite
    for i in required_bytes..bytes.len().min(32) {
        let remaining = &bytes[i..];

        // Check for common padding patterns
        if remaining.len() >= 4 {
            // NOP padding (0x90, 0x66 0x90, 0x0F 0x1F patterns)
            if remaining[0] == 0x90 ||
               (remaining[0] == 0x66 && remaining[1] == 0x90) ||
               (remaining[0] == 0x0F && remaining[1] == 0x1F) ||
               remaining[0] == 0xCC { // INT3 padding

                // Make sure we don't see another function start pattern after padding
                let safe_size = i + 4;
                if safe_size < bytes.len() {
                    let after_padding = &bytes[safe_size..];
                    // Check if there's another function that starts with common patterns
                    if after_padding.len() >= 2 {
                        // Don't extend if we see another function signature
                        if after_padding[0] == 0xB8 || // mov eax, immediate
                           after_padding[0] == 0x48 || // REX prefix (x64)
                           after_padding[0] == 0x55 || // push rbp
                           after_padding[0] == 0x89 || // mov instructions
                           after_padding[0] == 0xC3 {  // ret
                            debug!("Found potential function boundary at offset {}, limiting patch size", safe_size);
                            return Ok(0); // Don't extend beyond the first function
                        }
                    }
                }

                trace!("Found safe padding at offset {}, extending patch size to {}", i, safe_size);
                return Ok(safe_size);
            }
        }
    }

    // No suitable padding found
    Ok(0)
}

pub fn generate_trampoline(
    analysis: &PrologAnalysis,
    original_function: *const c_void,
    trampoline_address: *const c_void,
) -> InstructionResult<Vec<u8>> {
    debug!("Generating trampoline: original={:p}, trampoline={:p}",
           original_function, trampoline_address);

    if original_function.is_null() || trampoline_address.is_null() {
        error!("Null pointer provided to generate_trampoline");
        return Err(InstructionError::InvalidInstruction(0));
    }

    #[cfg(target_arch = "x86_64")]
    let mut assembler = CodeAssembler::new(64)?;
    #[cfg(target_arch = "x86")]
    let mut assembler = CodeAssembler::new(32)?;

    debug!("Copying {} original bytes to trampoline", analysis.original_bytes.len());
    assembler.db(&analysis.original_bytes)?;

    // Check if the original bytes end with a RET instruction (complete function)
    let ends_with_ret = analysis.original_bytes.last() == Some(&0xC3); // RET instruction

    if !ends_with_ret {
        let return_address = original_function as u64 + analysis.original_bytes.len() as u64;
        debug!("Adding absolute return jump to 0x{:X}", return_address);

        // Use absolute indirect jump for x64 to handle large distances
        #[cfg(target_arch = "x86_64")]
        {
            // Load return address into RAX and jump to it
            assembler.mov(iced_x86::code_asm::rax, return_address)?;
            assembler.jmp(iced_x86::code_asm::rax)?;
        }
        #[cfg(target_arch = "x86")]
        {
            assembler.jmp(return_address)?;
        }
    } else {
        debug!("Original bytes end with RET - no return jump needed");
    }

    trace!("Assembling trampoline at address 0x{:X}", trampoline_address as u64);
    let result = assembler.assemble(trampoline_address as u64)
        .map_err(|e| {
            error!("Trampoline assembly failed: {:?}", e);
            InstructionError::AssemblyError(format!("{:?}", e))
        })?;

    let trampoline_bytes: Vec<u8> = result.into_iter().collect();
    info!("Generated trampoline: {} bytes", trampoline_bytes.len());
    trace!("Trampoline bytes: {:02x?}", trampoline_bytes);

    Ok(trampoline_bytes)
}

/// Check if a relative jump can reach the target address
fn can_use_relative_jump(from_address: *const c_void, to_address: *const c_void) -> bool {
    let from = from_address as i64;
    let to = to_address as i64;
    let distance = to - from - 5; // 5 bytes for the jump instruction itself

    // x86-64 relative jumps use 32-bit signed displacement (±2GB range)
    distance >= i32::MIN as i64 && distance <= i32::MAX as i64
}

/// Generate a jump instruction to the detour function
pub fn generate_jump_to_detour(
    detour_address: *const c_void,
    patch_size: usize,
) -> InstructionResult<Vec<u8>> {
    generate_jump_to_detour_from(detour_address, patch_size, std::ptr::null())
}

/// Generate a jump instruction to the detour function from a specific address
pub fn generate_jump_to_detour_from(
    detour_address: *const c_void,
    patch_size: usize,
    from_address: *const c_void,
) -> InstructionResult<Vec<u8>> {
    debug!("Generating detour jump: target={:p}, patch_size={}",
           detour_address, patch_size);

    let arch = ArchConstants::current();

    if patch_size < arch.jump_instruction_size {
        error!("Patch size {} too small for jump instruction (need {})",
               patch_size, arch.jump_instruction_size);
        return Err(InstructionError::InsufficientBytes(arch.jump_instruction_size));
    }

    #[cfg(target_arch = "x86_64")]
    let mut assembler = CodeAssembler::new(64)?;
    #[cfg(target_arch = "x86")]
    let mut assembler = CodeAssembler::new(32)?;

    // For x64, check if we can use a 5-byte relative jump or need 12-byte absolute
    #[cfg(target_arch = "x86_64")]
    let (use_relative, actual_jump_size) = {
        if patch_size >= 12 {
            // We have space for absolute jump, but check if relative would work too
            if !from_address.is_null() && can_use_relative_jump(from_address, detour_address) {
                trace!("Using relative jump (5 bytes) - within range and space available");
                (true, 5)
            } else {
                trace!("Using absolute jump (12 bytes) - sufficient space available");
                (false, 12)
            }
        } else if patch_size >= 5 {
            // Only space for relative jump - check if it can reach
            if !from_address.is_null() && !can_use_relative_jump(from_address, detour_address) {
                error!("Relative jump cannot reach target: distance too large for 32-bit displacement");
                return Err(InstructionError::UnsafeHookLocation(
                    "Cannot use relative jump: target too far away (>2GB)".to_string()));
            }
            trace!("Using relative jump (5 bytes) - limited space, checking distance");
            (true, 5)
        } else {
            error!("Insufficient space for any jump: {} bytes", patch_size);
            return Err(InstructionError::InsufficientBytes(5));
        }
    };

    #[cfg(target_arch = "x86")]
    let (use_relative, actual_jump_size) = (true, 5);

    // Generate the appropriate jump
    #[cfg(target_arch = "x86_64")]
    {
        if use_relative {
            trace!("Adding relative jump instruction to 0x{:X}", detour_address as u64);
            // For relative jumps, we need to assemble at the actual target location
            // to get the correct relative displacement
            assembler.jmp(detour_address as u64)?;
        } else {
            trace!("Adding absolute jump instruction to 0x{:X}", detour_address as u64);
            assembler.mov(iced_x86::code_asm::rax, detour_address as u64)?;
            assembler.jmp(iced_x86::code_asm::rax)?;
        }
    }
    #[cfg(target_arch = "x86")]
    {
        trace!("Adding jump instruction to 0x{:X}", detour_address as u64);
        assembler.jmp(detour_address as u64)?;
    }

    // Pad with NOPs if needed
    if patch_size > actual_jump_size {
        let nop_count = patch_size - actual_jump_size;
        debug!("Adding {} NOP instructions for padding", nop_count);
        for i in 0..nop_count {
            trace!("Adding NOP #{}", i + 1);
            assembler.nop()?;
        }
    }

    trace!("Assembling detour jump");
    // For relative jumps, assemble at the actual source address to get correct displacement
    let assembly_address = if !from_address.is_null() { from_address as u64 } else { 0 };
    let result = assembler.assemble(assembly_address)
        .map_err(|e| {
            error!("Detour jump assembly failed: {:?}", e);
            InstructionError::AssemblyError(format!("{:?}", e))
        })?;

    let jump_bytes: Vec<u8> = result.into_iter().collect();
    info!("Generated detour jump: {} bytes ({})", jump_bytes.len(),
          if cfg!(target_arch = "x86_64") && use_relative { "relative" } else { "absolute" });
    trace!("Jump bytes: {:02x?}", jump_bytes);

    Ok(jump_bytes)
}

fn is_problematic_instruction(instruction: &Instruction) -> bool {
    match instruction.mnemonic() {
        Mnemonic::Jmp | Mnemonic::Call => true,
        Mnemonic::Jo | Mnemonic::Jno | Mnemonic::Jb | Mnemonic::Jae |
        Mnemonic::Je | Mnemonic::Jne | Mnemonic::Jbe | Mnemonic::Ja |
        Mnemonic::Js | Mnemonic::Jns | Mnemonic::Jp | Mnemonic::Jnp |
        Mnemonic::Jl | Mnemonic::Jge | Mnemonic::Jle | Mnemonic::Jg => true,
        Mnemonic::Loop | Mnemonic::Loope | Mnemonic::Loopne => true,
        Mnemonic::Ret | Mnemonic::Retf => true,
        Mnemonic::Int | Mnemonic::Into | Mnemonic::Iret | Mnemonic::Iretd | Mnemonic::Iretq => true,
        _ => false,
    }
}


impl From<CodeAssemblerResult> for InstructionError {
    fn from(err: CodeAssemblerResult) -> Self {
        InstructionError::AssemblyError(format!("{:?}", err))
    }
}
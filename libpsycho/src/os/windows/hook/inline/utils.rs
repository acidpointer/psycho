use std::ffi::c_void;

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, Encoder, FlowControl,
    Instruction, InstructionBlock, Mnemonic, OpKind, Register,
};

use super::InlineHookResult;
use super::errors::InlineHookError;
use crate::os::windows::constants::arch::BITNESS;
use crate::os::windows::winapi::{
    AllocationType, MEMORY_STATE_COMMIT, PageProtectionFlags, virtual_alloc, virtual_query,
};

/// Validates memory behind pointer and return protection flag and region size
/// # Arguments:
/// - `ptr` - Pointer to memory we want to check
pub fn validate_memory_access(ptr: *mut c_void) -> InlineHookResult<(PageProtectionFlags, usize)> {
    // First, we need to understand what memory behind pointer
    let mem_info = virtual_query(ptr)?;

    // Next, we check if memory is commited.
    // If not - it's obvious error, we cant work with not commited memory.
    if mem_info.state != MEMORY_STATE_COMMIT {
        log::error!("Memory at {:p} is not committed", ptr);
        return Err(InlineHookError::InaccessibleMemory);
    }

    // Fine, now let's check memory protection flag
    let protect = mem_info.protect;

    // We need to check if memory is executable.
    // This approach may be not so fast, but idiomatic and readable.
    let is_executable = match protect {
        PageProtectionFlags::PageExecute => true,
        PageProtectionFlags::PageExecuteRead => true,
        PageProtectionFlags::PageExecuteReadWrite => true,
        PageProtectionFlags::PageExecuteWriteCopy => true,

        // TODO: Check if it's correct
        PageProtectionFlags::PageGraphicsExecute => true,
        PageProtectionFlags::PageGraphicsExecuteRead => true,
        PageProtectionFlags::PageGraphicsExecuteReadWrite => true,
        _ => false,
    };

    // If memory is not executable, we return error.
    // Functions can be located only in executable memory.
    if !is_executable {
        log::error!("Memory at {:p} is not executable: {}", ptr, protect);
        return Err(InlineHookError::NonExecutableMemory);
    }

    log::trace!("Memory at {:p} validated successfully", ptr);

    // All fine, let's return protection flag and region size!
    Ok((protect, mem_info.region_size))
}

/// Check if current CPU architecture matches compiled target.
/// Only for: x86_64 and x86 targets!   
/// Validation works by disassembling some amount of instructions on some 'target' pointer.
/// Note: use carefull, better once at all.
pub fn validate_architecture(target: *mut c_void, max_read: usize) -> InlineHookResult<()> {
    const MIN_VALID_INSTRUCTIONS: i32 = 2;
    const MAX_CHECK_INSTRUCTIONS: i32 = 5;

    // Read enough bytes to decode several instructions
    let read_size = max_read.min(64);
    let mut buffer = vec![0u8; read_size];

    // TODO: explain safety
    unsafe {
        std::ptr::copy_nonoverlapping(target as *const u8, buffer.as_mut_ptr(), read_size);
    }

    // Try decoding as expected architecture
    let mut decoder = Decoder::new(BITNESS, &buffer, DecoderOptions::AMD);
    decoder.set_ip(target as u64);

    let mut valid_count = 0;
    let mut check_count = 0;

    while check_count < MAX_CHECK_INSTRUCTIONS && decoder.can_decode() {
        let mut instr = Instruction::default();
        decoder.decode_out(&mut instr);

        if !instr.is_invalid() {
            valid_count += 1;
        }
        check_count += 1;
    }

    // If we got enough valid instructions, architecture is probably correct
    if valid_count >= MIN_VALID_INSTRUCTIONS {
        log::trace!("Architecture validation passed for {}-bit", BITNESS);
        return Ok(());
    }

    // Try opposite architecture
    let opposite_bitness = if BITNESS == 64 { 32 } else { 64 };
    let mut opposite_decoder = Decoder::new(opposite_bitness, &buffer, DecoderOptions::AMD);
    opposite_decoder.set_ip(target as u64);

    let mut opposite_valid = 0;
    check_count = 0;

    while check_count < MAX_CHECK_INSTRUCTIONS && opposite_decoder.can_decode() {
        let mut instr = Instruction::default();
        opposite_decoder.decode_out(&mut instr);

        if !instr.is_invalid() {
            opposite_valid += 1;
        }
        check_count += 1;
    }

    // If opposite architecture decodes better, we have a mismatch
    if opposite_valid > valid_count && opposite_valid >= MIN_VALID_INSTRUCTIONS {
        return Err(InlineHookError::ArchitectureMismatch {
            expected: BITNESS,
            detected: opposite_bitness,
        });
    }

    // If neither decoded well, assume correct architecture
    log::trace!(
        "Architecture validation passed (default) for {}-bit",
        BITNESS
    );
    Ok(())
}

/// Allocates memory as close as possible to 'target' pointer with requested 'size'.
/// Returns pointer to allocated memory.
/// Probably you want to use this in trampoline, where it's important to locate trampoline
/// as close as possible to target, because limitations of CPU architecture
pub fn allocate_near_target(target: *mut c_void, size: usize) -> InlineHookResult<*mut c_void> {
    // First try to allocate near the target for x86_64
    #[cfg(target_arch = "x86_64")]
    {
        let target_addr = target as usize;
        let alignment = 0x10000usize; // 64KB alignment

        // Try different distances using exponential growth
        let mut distance = 0x1000usize; // Start at 4KB

        // We have 20 attempts, more than enougth!
        const MAX_ATTEMPTS: u32 = 20;

        for _ in 0..MAX_ATTEMPTS {
            // Try before target
            if let Some(addr) = target_addr.checked_sub(distance) {
                let aligned = (addr / alignment) * alignment;
                if let Ok(result) = virtual_alloc(
                    Some(aligned as *const c_void),
                    size,
                    AllocationType::CommitReserve,
                    PageProtectionFlags::PageExecuteReadWrite,
                ) {
                    log::trace!(
                        "Allocated near memory at {:p} ({}KB before target)",
                        result,
                        distance / 1024
                    );
                    return Ok(result);
                }
            }

            // Try after target
            if let Some(addr) = target_addr.checked_add(distance) {
                let aligned = (addr / alignment) * alignment;
                if let Ok(result) = virtual_alloc(
                    Some(aligned as *const c_void),
                    size,
                    AllocationType::CommitReserve,
                    PageProtectionFlags::PageExecuteReadWrite,
                ) {
                    log::trace!(
                        "Allocated near memory at {:p} ({}KB after target)",
                        result,
                        distance / 1024
                    );
                    return Ok(result);
                }
            }

            // Exponential growth up to 1GB
            distance = distance.saturating_mul(2).min(0x40000000);
        }
    }

    // Fallback to any address
    // Default on x86 target
    log::debug!("Falling back to any address allocation");
    virtual_alloc(
        None,
        size,
        AllocationType::CommitReserve,
        PageProtectionFlags::PageExecuteReadWrite,
    )
    .map_err(|_| InlineHookError::TrampolineAllocationFailed)
}

/// Calculate minimum instructions size for jump between two addresses.
/// The thing is, depends on distance between pointers, we need to select correct
/// jump instruction: relative or absolute jump.
/// When distance between pointers - 5 is between i32::MIN and i32::MAX, we can use
/// relative jump, it's a bit simplier and requires only 5 bytes of instructions!
/// That's why we do this to calulate distance: to - from - 5 // 5 bytes is requred for relative jump.
///
/// Otherwise, we use absulute jump with 14 bytes minimum instructions size!
///
/// But on x86 only relative jumps possible, so we instantly return 5 without any calculations.
/// Remember, for relative jumps we need distance between pointers: +- 2Gb and 5 bytes for instructions!
pub fn calculate_jump_size(from: *mut c_void, to: *mut c_void) -> InlineHookResult<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        let distance = (to as isize).wrapping_sub(from as isize).wrapping_sub(5);
        if distance >= i32::MIN as isize && distance <= i32::MAX as isize {
            log::trace!("Using 5-byte relative jump");
            Ok(5)
        } else {
            log::trace!("Using 14-byte absolute jump");
            Ok(14)
        }
    }

    #[cfg(target_arch = "x86")]
    {
        let _ = to;
        trace!("Using 5-byte jump for x86");
        Ok(5)
    }
}

/// Checks if given instruction is relocatible - possible to move to other location.
/// Yes, we cant just move all instruction bytes, it's known limitation of inline hooking.
/// If we try to do this - we get plain old undefined behaviour with fun debugging time, yay!
pub fn is_relocatable_instruction(instr: &Instruction) -> InlineHookResult<()> {
    // Check flow control
    match instr.flow_control() {
        FlowControl::Next => {
            // Check for RIP-relative addressing on x64
            #[cfg(target_arch = "x86_64")]
            {
                if instr.is_ip_rel_memory_operand() {
                    log::error!("RIP-relative instruction found: {:?}", instr.mnemonic());
                    return Err(InlineHookError::RipRelativeInstruction(instr.mnemonic()));
                }
            }
            Ok(())
        }
        _ => {
            log::error!("Non-relocatable flow control: {:?}", instr.mnemonic());
            Err(InlineHookError::NonRelocatableInstruction(instr.mnemonic()))
        }
    }
}

pub fn steal_bytes_safe(
    target: *mut c_void,
    min_size: usize,
    region_size: usize,
) -> InlineHookResult<(Vec<u8>, Vec<Instruction>)> {
    const MAX_INSTRUCTIONS: usize = 20;
    const MAX_STEAL_SIZE: usize = 64;

    log::debug!("Stealing at least {} bytes from {:p}", min_size, target);

    let mut stolen_bytes = Vec::new();
    let mut stolen_instructions = Vec::new();
    let mut stolen_size = 0usize;

    // Calculate safe read size within memory region
    let target_offset = (target as usize) % 0x1000; // Offset within page
    let safe_read_size = (0x1000 - target_offset).min(region_size).min(128);

    if safe_read_size < min_size {
        return Err(InlineHookError::UnsafeMemoryRegion {
            safe: safe_read_size,
            requested: min_size,
        });
    }

    let mut buffer = vec![0u8; safe_read_size];

    unsafe {
        std::ptr::copy_nonoverlapping(target as *const u8, buffer.as_mut_ptr(), safe_read_size);
    }

    // We use DecoderOptions::AMD because it provide slightly better compatibility while
    // still supports Intel
    let mut decoder = Decoder::new(BITNESS, &buffer, DecoderOptions::AMD);
    decoder.set_ip(target as u64);

    while stolen_size < min_size {
        if stolen_instructions.len() >= MAX_INSTRUCTIONS {
            log::error!("Too many instructions to steal");

            return Err(InlineHookError::InsufficientSpace {
                needed: min_size,
                available: stolen_size,
            });
        }

        if !decoder.can_decode() {
            log::error!("Cannot decode more instructions");
            return Err(InlineHookError::DisassemblyFailed);
        }

        let mut instruction = Instruction::default();

        decoder.decode_out(&mut instruction);

        if instruction.is_invalid() {
            log::error!("Invalid instruction encountered at offset {}", stolen_size);
            return Err(InlineHookError::DisassemblyFailed);
        }

        // Check if instruction is relocatable
        is_relocatable_instruction(&instruction)?;

        let instr_len = instruction.len();
        if stolen_size + instr_len > MAX_STEAL_SIZE {
            log::error!("Stealing too many bytes");

            return Err(InlineHookError::InsufficientSpace {
                needed: min_size,
                available: stolen_size,
            });
        }

        if stolen_size + instr_len > safe_read_size {
            log::error!("Would exceed safe read boundary");
            return Err(InlineHookError::UnsafeMemoryRegion {
                safe: safe_read_size,
                requested: stolen_size + instr_len,
            });
        }

        log::trace!("Decoded relocatable instruction of {} bytes", instr_len);

        stolen_bytes.extend_from_slice(&buffer[stolen_size..stolen_size + instr_len]);
        stolen_instructions.push(instruction);
        stolen_size += instr_len;
    }

    log::debug!(
        "Successfully stole {} bytes with {} instructions",
        stolen_size,
        stolen_instructions.len()
    );
    Ok((stolen_bytes, stolen_instructions))
}

/// Relocate instructions from old to new base
pub fn relocate_instructions(
    instructions: &[Instruction],
    old_base: *mut c_void,
    new_base: *mut c_void,
) -> InlineHookResult<Vec<u8>> {
    log::debug!(
        "Relocating {} instructions from {:p} to {:p}",
        instructions.len(),
        old_base,
        new_base
    );

    if instructions.is_empty() {
        return Err(InlineHookError::EncodingError(
            "No instructions to relocate".to_string(),
        ));
    }

    let mut relocated = Vec::with_capacity(instructions.len());
    let mut current_offset = 0u64;

    for instr in instructions {
        let mut new_instr = *instr;
        new_instr.set_ip((new_base as u64) + (current_offset as u64));

        // Note: BlockEncoder will handle most relocations, but we've already
        // rejected RIP-relative instructions in is_relocatable_instruction
        relocated.push(new_instr);
        current_offset += instr.len() as u64;
    }

    let block = InstructionBlock::new(&relocated, new_base as u64);

    // Use RETURN_NEW_INSTRUCTION_OFFSETS for better debugging
    let encoded = BlockEncoder::encode(
        BITNESS,
        block,
        BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
    )?;

    if encoded.code_buffer.is_empty() {
        return Err(InlineHookError::EncodingError(
            "Empty encoding result".to_string(),
        ));
    }

    log::debug!(
        "Successfully relocated instructions to {} bytes",
        encoded.code_buffer.len()
    );

    Ok(encoded.code_buffer)
}

/// Generate bytes for jump between 'from' and 'to' addresses
pub fn create_jump_bytes(from: *mut c_void, to: *mut c_void) -> InlineHookResult<Vec<u8>> {
    log::debug!("Creating jump from {:p} to {:p}", from, to);

    let from_addr = from as u64;
    let to_addr = to as u64;

    #[cfg(target_arch = "x86_64")]
    {
        let distance = (to_addr as i64)
            .wrapping_sub(from_addr as i64)
            .wrapping_sub(5);

        if distance >= i32::MIN as i64 && distance <= i32::MAX as i64 {
            log::trace!("Creating near jump");
            let mut instr = Instruction::with_branch(Code::Jmp_rel32_64, to_addr)?;
            instr.set_ip(from_addr);

            let mut encoder = Encoder::new(BITNESS);
            let result = encoder.encode(&instr, from_addr)?;

            if result != instr.len() {
                return Err(InlineHookError::EncodingError(
                    "Encoding size mismatch".to_string(),
                ));
            }

            let buffer = encoder.take_buffer();
            if buffer.len() != 5 {
                return Err(InlineHookError::EncodingError(format!(
                    "Expected 5 bytes for near jump, got {}",
                    buffer.len()
                )));
            }

            Ok(buffer)
        } else {
            log::trace!("Creating far jump through memory");

            // For far jumps, we need to manually construct the instruction
            // jmp [rip+0] followed by the absolute address
            //
            // As you can see, iced-x86 allows us to literally construct instructions!
            let mut instr = Instruction::default();
            instr.set_code(Code::Jmp_rm64);
            instr.set_op0_kind(OpKind::Memory);
            instr.set_memory_base(Register::RIP);
            instr.set_memory_displacement64(0);

            let mut encoder = Encoder::new(BITNESS);
            let encoded_len = encoder.encode(&instr, from_addr)?;

            if encoded_len != 6 {
                return Err(InlineHookError::EncodingError(format!(
                    "Expected 6 bytes for indirect jump, got {}",
                    encoded_len
                )));
            }

            let mut bytes = encoder.take_buffer();
            bytes.extend_from_slice(&to_addr.to_le_bytes());

            if bytes.len() != 14 {
                return Err(InlineHookError::EncodingError(format!(
                    "Expected 14 bytes for far jump, got {}",
                    bytes.len()
                )));
            }

            Ok(bytes)
        }
    }

    #[cfg(target_arch = "x86")]
    {
        let distance = (to_addr as i32)
            .wrapping_sub(from_addr as i32)
            .wrapping_sub(5);

        log::trace!("Creating x86 near jump");
        let mut instr = Instruction::with_branch(Code::Jmp_rel32_32, to_addr)?;
        instr.set_ip(from_addr);

        let mut encoder = Encoder::new(BITNESS);
        let result = encoder
            .encode(&instr, from_addr)
            .map_err(|e| InlineHookError::EncodingError(format!("{:?}", e)))?;

        if result != instr.len() {
            return Err(InlineHookError::EncodingError(
                "Encoding size mismatch".to_string(),
            ));
        }

        let buffer = encoder.take_buffer();
        if buffer.len() != 5 {
            return Err(InlineHookError::EncodingError(format!(
                "Expected 5 bytes for x86 jump, got {}",
                buffer.len()
            )));
        }

        return Ok(buffer);
    }
}

/// Verify generated bytes for jump for correctness
pub fn verify_jump_bytes(
    jump_bytes: &[u8],
    from: *mut c_void,
    expected_target: *mut c_void,
) -> InlineHookResult<()> {
    let mut decoder = Decoder::new(BITNESS, jump_bytes, DecoderOptions::AMD);
    decoder.set_ip(from as u64);

    let mut instruction = Instruction::default();
    if !decoder.can_decode() {
        return Err(InlineHookError::JumpVerificationFailed {
            expected: expected_target,
            actual: std::ptr::null_mut(),
        });
    }

    decoder.decode_out(&mut instruction);

    if instruction.is_invalid() {
        return Err(InlineHookError::JumpVerificationFailed {
            expected: expected_target,
            actual: std::ptr::null_mut(),
        });
    }

    // Verify it's a jump instruction
    if instruction.mnemonic() != Mnemonic::Jmp {
        log::error!(
            "Generated instruction is not a jump: {:?}",
            instruction.mnemonic()
        );
        return Err(InlineHookError::EncodingError(
            "Not a jump instruction".to_string(),
        ));
    }

    // Check the instruction code to determine jump type
    match instruction.code() {
        Code::Jmp_rel32_32 | Code::Jmp_rel32_64 => {
            // Near jump - verify target
            let actual_target = instruction.near_branch_target();
            if actual_target != expected_target as u64 {
                return Err(InlineHookError::JumpVerificationFailed {
                    expected: expected_target,
                    actual: actual_target as *mut c_void,
                });
            }
        }

        // Here we check for case with far jumps.
        // For us verification of the absolute address is quite problematic, but
        // at this point we sure that indirect jump instruction is correct.
        Code::Jmp_rm64 | Code::Jmp_rm32 => {
            log::trace!("Indirect jump instruction verified (target validation skipped)");
        }
        _ => {
            log::error!("Unexpected jump code: {:?}", instruction.code());
            return Err(InlineHookError::EncodingError(format!(
                "Unexpected jump instruction code: {:?}",
                instruction.code()
            )));
        }
    }

    log::trace!("Jump instruction verified successfully");
    Ok(())
}

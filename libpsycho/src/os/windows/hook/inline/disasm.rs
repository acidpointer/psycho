#![allow(dead_code)]

use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, FlowControl, InstructionBlock};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

use libc::c_void;
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;

use crate::os::windows::hook::inline::errors::DisasmError;

use crate::ffi::BITNESS;
use crate::os::windows::winapi::{AllocationType, virtual_alloc};

pub type DisasmResult<T> = Result<T, DisasmError>;

/// Wrapped instruction with additional functionality
pub struct DisasmInstruction {
    instruction: Instruction,
}

impl DisasmInstruction {
    pub fn new(instruction: Instruction) -> Self {
        Self { instruction }
    }

    /// Returns inner 'instruction' from 'iced_x86'
    pub fn inner(&self) -> &Instruction {
        &self.instruction
    }

    /// Returns the instructions relative branch offset, if applicable.
    pub fn relative_branch_target(&self) -> Option<u64> {
        use OpKind::*;

        match self.instruction.op0_kind() {
            NearBranch16 | NearBranch32 | NearBranch64 => {
                Some(self.instruction.near_branch_target())
            }
            _ => None,
        }
    }

    /// Returns the instructions RIP operand displacement if applicable.
    pub fn rip_operand_target(&self) -> Option<u64> {
        self.instruction
            .op_kinds()
            .find(|op| *op == OpKind::Memory && self.instruction.memory_base() == Register::RIP)
            .map(|_| self.instruction.memory_displacement64())
    }

    /// Returns true if this instruction any type of a loop.
    pub fn is_loop(&self) -> bool {
        use Mnemonic::*;
        matches!(
            self.instruction.mnemonic(),
            Loop | Loope | Loopne | Jecxz | Jcxz
        )
    }

    /// Returns true if this instruction is an unconditional jump.
    pub fn is_unconditional_jump(&self) -> bool {
        self.instruction.mnemonic() == Mnemonic::Jmp
    }

    /// Returns true if this instruction is a function call.
    pub fn is_call(&self) -> bool {
        self.instruction.mnemonic() == Mnemonic::Call
    }

    /// Returns true if this instruction is a return.
    pub fn is_return(&self) -> bool {
        self.instruction.mnemonic() == Mnemonic::Ret
    }

    /// Returns true if this instruction is invalid.
    pub fn is_invalid(&self) -> bool {
        self.instruction.is_invalid()
    }

    /// Returns the 64-bit IP of the instruction
    /// You want to use it on RIP cases
    pub fn ip(&self) -> u64 {
        self.instruction.ip()
    }

    /// Returns size of instruction in bytes
    pub fn len(&self) -> usize {
        self.instruction.len()
    }

    /// Returns the memory operand's displacement or the 64-bit absolute address if it's an EIP or RIP relative memory operand
    pub fn memory_displacement64(&self) -> u64 {
        self.instruction.memory_displacement64()
    }

    /// Returns the memory operand's displacement or the 32-bit absolute address if it's an EIP or RIP relative memory operand
    pub fn memory_displacement32(&self) -> u32 {
        self.instruction.memory_displacement32()
    }

    /// Returns `true` if current instruction is relocatible
    pub fn is_relocatable(&self) -> bool {
        match self.instruction.flow_control() {
            FlowControl::Next => {
                // Check for RIP-relative addressing on x64
                #[cfg(target_arch = "x86_64")]
                {
                    if self.instruction.is_ip_rel_memory_operand() {
                        return false;
                    }
                }

                // On x86 we not deal with RIP-relative addressing at all
                true
            }
            _ => false,
        }
    }
}

/// Disassembly result for target function to hook
///
/// It is often implemented in different way, but Disasm is attempt
/// to provide more clean and easy disassembler for inline hooking
pub struct Disasm {
    jump_size: usize,
    stolen_bytes: Vec<u8>,
    stolen_bytes_len: usize,
    stolen_instructions: Vec<DisasmInstruction>,
    target_ptr: *const c_void,
}

impl Disasm {
    /// Calculate minimum instructions size for jump between two addresses.
    ///
    /// The thing is, depends on distance between pointers, we need to select correct
    /// jump instruction: relative or absolute jump.
    /// When distance between pointers - 5 is between `i32::MIN` and `i32::MAX`, we can use
    /// relative jump, it's a bit simplier and requires only 5 bytes of instructions!
    /// That's why we do this to calulate distance: `to - from - 5`, where 5 means requred bytes for relative jump.
    ///
    /// Otherwise, we use absulute jump with 14 bytes minimum instructions size!
    ///
    /// But on x86 only relative jumps possible, so we instantly return 5 without any calculations.
    /// Remember, for relative jumps we need distance between pointers: +- 2Gb and 5 bytes for instructions!
    fn calculate_jump_size(from: *const c_void, to: *const c_void) -> usize {
        #[cfg(target_arch = "x86_64")]
        {
            // Calculate the displacement between two functions.
            // We add 5 bytes to include JMP instruction size itself.
            // If displacement is 32-bit integer, e.g. fits in 2Gb range, we can use
            // simple relative Jump which is 5 byte.
            // Otherwise, we use absolute jump which is 14 bytes.
            // Relative jump: JMP rel32
            // Absolute jump: JMP [rip+0], <addr>
            let distance = (to as isize).wrapping_sub(from as isize).wrapping_sub(5);
            if distance >= i32::MIN as isize && distance <= i32::MAX as isize {
                crate::ffi::JUMP_REL_MIN_SIZE
            } else {
                crate::ffi::JUMP_ABS_MIN_SIZE
            }
        }

        #[cfg(target_arch = "x86")]
        {
            crate::ffi::JUMP_REL_MIN_SIZE
        }
    }

    /// Disassembles memory range between `target_ptr` and `detour_ptr`
    /// and constructs new `Disasm`
    ///
    /// # Arguments
    /// - `target_ptr` - raw pointer to target function, which is region start
    /// - `detour_ptr` - raw pointer to detour function, which is region end
    pub fn from_memory_range(
        target_ptr: *const c_void,
        detour_ptr: *const c_void,
    ) -> DisasmResult<Self> {
        let jump_size = Self::calculate_jump_size(target_ptr, detour_ptr);

        #[cfg(target_arch = "x86_64")]
        let bitness = 64;

        #[cfg(target_arch = "x86")]
        let bitness = 32;

        // Size of the buffer, used in Decoder.
        // What means 16 here?
        // First of all, we need to understand that on x86_64 maximum instruction size is 15 bytes.
        // Additional 16 bytes is only safe barrier to protect us from monster size last instruction.
        let buffer_size = jump_size + 16;

        let mut decoder = Decoder::with_ip(
            bitness,
            unsafe { std::slice::from_raw_parts(target_ptr as *const u8, buffer_size) },
            target_ptr as u64, // The instruction pointer (base address)
            DecoderOptions::NONE,
        );

        // Amount of bytes we successfully steal from memory
        let mut stolen_bytes_len = 0;

        // Vector with disassembled instructions
        let mut stolen_instructions: Vec<DisasmInstruction> = vec![];

        while stolen_bytes_len < jump_size {
            let mut instruction = Instruction::default();

            decoder.decode_out(&mut instruction);

            let instr = DisasmInstruction::new(instruction);

            if instr.is_invalid() {
                // Yeeee, we found invalid instruction! Fantastic!
                // For us - it is obvious error, so we throw error here
                return Err(DisasmError::InvalidInstruction);
            }

            // If we find any control flow before we have enough
            // bytes for our JMP, we must abort.
            if instr.is_return() || instr.is_unconditional_jump() || instr.is_loop() {
                return Err(DisasmError::ShortTarget);
            }

            // Ooops, RIP-relative instruction, damn.
            // We handle it later, when we will create trampoline.
            // As for now we just log this case.
            if let Some(_target) = instr.rip_operand_target() {
                log::debug!("Found RIP-relative instruction at 0x{:X}", instr.ip());
            }

            stolen_instructions.push(instr);
            stolen_bytes_len += instruction.len();
        }

        let stolen_bytes =
            unsafe { std::slice::from_raw_parts(target_ptr as *const u8, stolen_bytes_len) }
                .to_vec();

        Ok(Disasm {
            stolen_instructions,
            stolen_bytes_len,
            stolen_bytes,
            jump_size,
            target_ptr,
        })
    }

    /// Allocates memory as close as possible to `target_ptr`
    ///
    /// # Arguments
    /// - `size` - memory size in bytes
    pub fn allocate_near_target(&self, size: usize) -> DisasmResult<*mut c_void> {
        #[cfg(target_arch = "x86_64")]
        {
            let target_addr = self.target_ptr as usize;
            let alignment = 0x10000usize; // 64KB alignment

            // Try different distances using exponential growth
            let mut distance = 0x1000usize; // Start at 4KB

            // We have 20 attempts, more than enougth!
            const MAX_ATTEMPTS: u32 = 20;

            for _ in 0..MAX_ATTEMPTS {
                // Try allocate before target
                if let Some(addr) = target_addr.checked_sub(distance) {
                    let aligned_addr = (addr / alignment) * alignment;

                    let ptr = unsafe {
                        virtual_alloc(
                            Some(aligned_addr as *const c_void),
                            size,
                            AllocationType::CommitReserve,
                            PAGE_EXECUTE_READWRITE,
                        )?
                    };

                    log::trace!(
                        "Allocated near memory at {:p} ({}KB before target)",
                        ptr,
                        distance / 1024
                    );

                    return Ok(ptr);
                }

                // Try after target
                if let Some(addr) = target_addr.checked_add(distance) {
                    let aligned_addr = (addr / alignment) * alignment;

                    let ptr = unsafe {
                        virtual_alloc(
                            Some(aligned_addr as *const c_void),
                            size,
                            AllocationType::CommitReserve,
                            PAGE_EXECUTE_READWRITE,
                        )?
                    };

                    log::trace!(
                        "Allocated after memory at {:p} ({}KB after target)",
                        ptr,
                        distance / 1024
                    );

                    return Ok(ptr);
                }

                // Exponential growth up to 1GB
                distance = distance.saturating_mul(2).min(0x40000000);
            }
        }

        // Fallback to any address
        // Default on x86 target
        log::debug!("Falling back to any address allocation");
        let ptr = unsafe {
            virtual_alloc(
                None,
                size,
                AllocationType::CommitReserve,
                PAGE_EXECUTE_READWRITE,
            )?
        };

        Ok(ptr)
    }

    /// Relocate instructions from `target_ptr` to pre-allocated trampoline memory
    ///  
    /// # Arguments
    /// - `trampoline_memory_ptr` - Pointer to allocated trampoline memory
    ///
    /// # Safety
    /// Caller responsible to handle trampoline allocation. Wrong memory pointer will
    /// lead to UB or other bugs which hard to debug.
    /// Please, use `Trampoline`
    pub fn relocate_instructions(
        &self,
        trampoline_memory_ptr: *mut c_void,
    ) -> DisasmResult<Vec<u8>> {
        let instr_len = self.stolen_instructions.len();

        log::debug!(
            "Relocating {} instructions from {:p} to {:p}",
            instr_len,
            self.target_ptr,
            trampoline_memory_ptr
        );

        if self.stolen_instructions.is_empty() {
            return Err(DisasmError::EncodingError(
                "No instructions to relocate".to_string(),
            ));
        }

        let mut relocated = Vec::with_capacity(instr_len);
        let mut current_offset = 0u64;

        for disasm_instr in &self.stolen_instructions {
            let mut new_instr = *disasm_instr.inner();

            new_instr.set_ip((trampoline_memory_ptr as u64) + current_offset);

            // Note: BlockEncoder will handle most relocations, but we've already
            // rejected RIP-relative instructions in is_relocatable_instruction
            relocated.push(new_instr);
            current_offset += disasm_instr.len() as u64;
        }

        let block = InstructionBlock::new(&relocated, trampoline_memory_ptr as u64);

        // Use RETURN_NEW_INSTRUCTION_OFFSETS for better debugging
        let encoded = BlockEncoder::encode(
            BITNESS,
            block,
            BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
        )?;

        if encoded.code_buffer.is_empty() {
            return Err(DisasmError::EncodingError(
                "Empty encoding result".to_string(),
            ));
        }

        log::debug!(
            "Successfully relocated instructions to {} bytes",
            encoded.code_buffer.len()
        );

        Ok(encoded.code_buffer)
    }

    /// Returns minimum needed amount of bytes for Jump instruction.
    ///
    /// This value depends on several factors, but in short words:
    /// - 14 - absolute jump, only x86_64 and only if distance between target and detour pointers > 2Gb
    /// - 5  - relative jump, x86 or x86_64, if distance between target and detour pointers <= 2Gb OR we are on x86
    pub fn get_jump_size(&self) -> usize {
        self.jump_size
    }

    /// Returns amount of stolen bytes
    pub fn get_stolen_bytes_len(&self) -> usize {
        self.stolen_bytes_len
    }

    /// Returns reference to stolen bytes vector
    pub fn get_stolen_bytes_ref(&self) -> &Vec<u8> {
        &self.stolen_bytes
    }

    /// Returns all RIP-relative instructions from this disassembly result
    pub fn rip_relative_instructions(&self) -> Vec<&DisasmInstruction> {
        self.stolen_instructions
            .iter()
            .filter(|instr| instr.rip_operand_target().is_some())
            .collect()
    }

    /// Returns all relative branch instructions from this disassembly result
    pub fn relative_branch_instructions(&self) -> Vec<&DisasmInstruction> {
        self.stolen_instructions
            .iter()
            .filter(|instr| instr.relative_branch_target().is_some())
            .collect()
    }

    /// Returns pointer of disassembly target (target function)
    pub fn get_target_ptr(&self) -> *const c_void {
        self.target_ptr
    }
}

/// Generate bytes
pub(super) fn create_jump_bytes(from: *mut c_void, to: *mut c_void) -> DisasmResult<Vec<u8>> {
    log::debug!("Creating jump from {:p} to {:p}", from, to);

    let from_addr = from as u64;
    let to_addr = to as u64;

    #[cfg(target_arch = "x86_64")]
    {
        let distance = (to_addr as i64)
            .wrapping_sub(from_addr as i64)
            .wrapping_sub(5);

        if distance >= i32::MIN as i64 && distance <= i32::MAX as i64 {
            use iced_x86::{Code, Encoder};

            use crate::ffi::BITNESS;

            log::trace!("Creating near(relative) jump");
            let mut instr = Instruction::with_branch(Code::Jmp_rel32_64, to_addr)?;
            instr.set_ip(from_addr);

            let mut encoder = Encoder::new(BITNESS);
            let result = encoder.encode(&instr, from_addr)?;

            if result != instr.len() {
                return Err(DisasmError::EncodingError(
                    "Encoding size mismatch".to_string(),
                ));
            }

            let buffer = encoder.take_buffer();
            if buffer.len() != 5 {
                return Err(DisasmError::EncodingError(format!(
                    "Expected 5 bytes for near jump, got {}",
                    buffer.len()
                )));
            }

            Ok(buffer)
        } else {
            use iced_x86::{Code, Encoder, OpKind, Register};

            use crate::ffi::BITNESS;

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
                return Err(DisasmError::EncodingError(format!(
                    "Expected 6 bytes for indirect jump, got {}",
                    encoded_len
                )));
            }

            let mut bytes = encoder.take_buffer();
            bytes.extend_from_slice(&to_addr.to_le_bytes());

            if bytes.len() != 14 {
                return Err(DisasmError::EncodingError(format!(
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
) -> DisasmResult<()> {
    let mut decoder = Decoder::new(BITNESS, jump_bytes, DecoderOptions::AMD);
    decoder.set_ip(from as u64);

    let mut instruction = Instruction::default();
    if !decoder.can_decode() {
        return Err(DisasmError::JumpVerificationFailed(
            expected_target as usize,
            0,
        ));
    }

    decoder.decode_out(&mut instruction);

    if instruction.is_invalid() {
        return Err(DisasmError::JumpVerificationFailed(
            expected_target as usize,
            0,
        ));
    }

    // Verify it's a jump instruction
    if instruction.mnemonic() != Mnemonic::Jmp {
        log::error!(
            "Generated instruction is not a jump: {:?}",
            instruction.mnemonic()
        );
        return Err(DisasmError::EncodingError(
            "Not a jump instruction".to_string(),
        ));
    }

    // Check the instruction code to determine jump type
    match instruction.code() {
        Code::Jmp_rel32_32 | Code::Jmp_rel32_64 => {
            // Near jump - verify target
            let actual_target = instruction.near_branch_target();
            if actual_target != expected_target as u64 {
                return Err(DisasmError::JumpVerificationFailed(
                    expected_target as usize,
                    actual_target as usize,
                ));
            }
        }

        // Here we check for case with far jumps.
        // For us verification of the absolute address is quite problematic, but
        // at this point we sure that indirect jump instruction is correct.
        Code::Jmp_rm64 | Code::Jmp_rm32 => {
            log::trace!("Indirect jump instruction verified (target validation skipped)");
        }
        _ => {
            return Err(DisasmError::EncodingError(format!(
                "Unexpected jump instruction code: {:?}",
                instruction.code()
            )));
        }
    }

    log::trace!("Jump instruction verified successfully");
    Ok(())
}


// pub fn steal_bytes_safe(
//     target: *mut c_void,
//     min_size: usize,
//     region_size: usize,
// ) -> InlineHookResult<(Vec<u8>, Vec<Instruction>)> {
//     const MAX_INSTRUCTIONS: usize = 20;
//     const MAX_STEAL_SIZE: usize = 64;

//     log::debug!("Stealing at least {} bytes from {:p}", min_size, target);

//     let mut stolen_bytes = Vec::new();
//     let mut stolen_instructions = Vec::new();
//     let mut stolen_size = 0usize;

//     // Calculate safe read size within memory region
//     let target_offset = (target as usize) % 0x1000; // Offset within page
//     let safe_read_size = (0x1000 - target_offset).min(region_size).min(128);

//     if safe_read_size < min_size {
//         return Err(InlineHookError::UnsafeMemoryRegion {
//             safe: safe_read_size,
//             requested: min_size,
//         });
//     }

//     let mut buffer = vec![0u8; safe_read_size];

//     unsafe {
//         std::ptr::copy_nonoverlapping(target as *const u8, buffer.as_mut_ptr(), safe_read_size);
//     }

//     // We use DecoderOptions::AMD because it provide slightly better compatibility while
//     // still supports Intel
//     let mut decoder = Decoder::new(BITNESS, &buffer, DecoderOptions::AMD);
//     decoder.set_ip(target as u64);

//     while stolen_size < min_size {
//         if stolen_instructions.len() >= MAX_INSTRUCTIONS {
//             log::error!("Too many instructions to steal");

//             return Err(InlineHookError::InsufficientSpace {
//                 needed: min_size,
//                 available: stolen_size,
//             });
//         }

//         if !decoder.can_decode() {
//             log::error!("Cannot decode more instructions");
//             return Err(InlineHookError::DisassemblyFailed);
//         }

//         let mut instruction = Instruction::default();

//         decoder.decode_out(&mut instruction);

//         if instruction.is_invalid() {
//             log::error!("Invalid instruction encountered at offset {}", stolen_size);
//             return Err(InlineHookError::DisassemblyFailed);
//         }

//         // Check if instruction is relocatable
//         is_relocatable_instruction(&instruction)?;

//         let instr_len = instruction.len();
//         if stolen_size + instr_len > MAX_STEAL_SIZE {
//             log::error!("Stealing too many bytes");

//             return Err(InlineHookError::InsufficientSpace {
//                 needed: min_size,
//                 available: stolen_size,
//             });
//         }

//         if stolen_size + instr_len > safe_read_size {
//             log::error!("Would exceed safe read boundary");
//             return Err(InlineHookError::UnsafeMemoryRegion {
//                 safe: safe_read_size,
//                 requested: stolen_size + instr_len,
//             });
//         }

//         log::trace!("Decoded relocatable instruction of {} bytes", instr_len);

//         stolen_bytes.extend_from_slice(&buffer[stolen_size..stolen_size + instr_len]);
//         stolen_instructions.push(instruction);
//         stolen_size += instr_len;
//     }

//     log::debug!(
//         "Successfully stole {} bytes with {} instructions",
//         stolen_size,
//         stolen_instructions.len()
//     );
//     Ok((stolen_bytes, stolen_instructions))
// }


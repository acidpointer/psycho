#![allow(dead_code)]

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, Encoder, FlowControl,
    Instruction, InstructionBlock, Mnemonic, OpKind, Register,
};

use libc::c_void;
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;

use super::errors::DisasmError;

use crate::ffi::BITNESS;
use crate::os::windows::winapi::{AllocationType, virtual_alloc};

pub type DisasmResult<T> = Result<T, DisasmError>;

/// Wrapped instruction with additional functionality
pub struct DisasmInstruction {
    instruction: Instruction,
    is_rip_relative: bool,
}

impl DisasmInstruction {
    pub fn new(instruction: Instruction) -> Self {
        Self {
            instruction,
            is_rip_relative: false,
        }
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

    has_rip_relative: bool,
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
    #[allow(unused_variables)]
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

        let mut has_rip_relative = false;

        while stolen_bytes_len < jump_size {
            let mut instruction = Instruction::default();

            decoder.decode_out(&mut instruction);

            let mut instr = DisasmInstruction::new(instruction);

            // Yeeee, we found invalid instruction! Fantastic!
            // For us - it is obvious error, so we throw error here
            if instr.is_invalid() {
                return Err(DisasmError::InvalidInstruction);
            }

            // Log detailed instruction information for debugging
            log::trace!(
                "Stolen instruction at 0x{:X}: mnemonic={:?}, len={}, flow_control={:?}",
                instr.ip(),
                instr.inner().mnemonic(),
                instr.len(),
                instr.inner().flow_control()
            );

            // If we find certain control flow instructions, we cannot safely hook.
            // - Returns/Unconditional Jumps: Function ends before we have enough bytes
            // - Loops: Complex control flow that's difficult to relocate correctly
            // Note: CALL and conditional branches CAN be relocated by BlockEncoder
            if instr.is_return() || instr.is_unconditional_jump() || instr.is_loop() {
                log::error!(
                    "Cannot hook: found terminating instruction at 0x{:X}: {:?}",
                    instr.ip(),
                    instr.inner().mnemonic()
                );
                return Err(DisasmError::ShortTarget);
            }

            // Check for IP-relative memory operands (RIP on x64, EIP on x86).
            // On x64, these are common and BlockEncoder can handle them if trampoline is within ±2GB.
            // On x86, these are rare but also relocatable within the 4GB address space.
            // We log them for debugging but allow BlockEncoder to handle the relocation.
            if let Some(target) = instr.rip_operand_target() {
                log::debug!(
                    "Found RIP-relative instruction at 0x{:X} targeting 0x{:X}",
                    instr.ip(),
                    target
                );

                instr.is_rip_relative = true;

                // We save flag to inform Disasm object that
                // it contains some RIP-relative instructions
                if !has_rip_relative {
                    has_rip_relative = true;
                }
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
            has_rip_relative,
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

                    let alloc_result = unsafe {
                        virtual_alloc(
                            Some(aligned_addr as *const c_void),
                            size,
                            AllocationType::CommitReserve,
                            PAGE_EXECUTE_READWRITE,
                        )
                    };

                    match alloc_result {
                        Ok(ptr) => {
                            log::trace!(
                                "Allocated near memory at {:p} ({}KB before target at {:p})",
                                ptr,
                                distance / 1024,
                                self.target_ptr,
                            );

                            return Ok(ptr);
                        }
                        Err(err) => {
                            log::trace!(
                                "Failed to allocate at {} before target at {:p} with error: {}",
                                distance,
                                self.target_ptr,
                                err
                            );
                        }
                    }
                }

                // Try after target
                if let Some(addr) = target_addr.checked_add(distance) {
                    let aligned_addr = (addr / alignment) * alignment;

                    let alloc_result = unsafe {
                        virtual_alloc(
                            Some(aligned_addr as *const c_void),
                            size,
                            AllocationType::CommitReserve,
                            PAGE_EXECUTE_READWRITE,
                        )
                    };

                    match alloc_result {
                        Ok(ptr) => {
                            log::trace!(
                                "Allocated after memory at {:p} ({}KB after target)",
                                ptr,
                                distance / 1024
                            );

                            return Ok(ptr);
                        }
                        Err(err) => {
                            log::trace!("Failed to allocate at {} after target: {}", distance, err);
                        }
                    }
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
    /// This uses manual instruction relocation similar to retour-rs approach:
    /// - CALL instructions are manually regenerated with correct displacement
    /// - Conditional jumps (Jcc) are handled specially (copied if internal, expanded if external)
    /// - Other instructions use BlockEncoder for automatic relocation
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
        use super::thunk;

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

        // Track internal branch targets
        let mut internal_branch_target: Option<u64> = None;

        // Calculate the range of stolen bytes in original code
        let prolog_start = self.target_ptr as u64;
        let prolog_end = prolog_start + (self.stolen_bytes_len as u64);

        // Build relocated code byte-by-byte
        let mut relocated_bytes = Vec::with_capacity(self.stolen_bytes_len + 32);
        let mut original_offset = 0usize;

        for (idx, disasm_instr) in self.stolen_instructions.iter().enumerate() {
            let instr = disasm_instr.inner();
            let instr_len = instr.len();

            // Current address in trampoline where this instruction will be placed
            let trampoline_instr_addr = (trampoline_memory_ptr as usize) + relocated_bytes.len();

            // Original instruction bytes
            let instr_bytes = &self.stolen_bytes[original_offset..original_offset + instr_len];

            log::trace!(
                "Processing instruction #{}: {:?} at original 0x{:X}, trampoline 0x{:X}",
                idx,
                instr.mnemonic(),
                instr.ip(),
                trampoline_instr_addr
            );

            // Check if this is a CALL instruction
            if instr.is_call_near()
                && let Some(target_addr) = disasm_instr.relative_branch_target() {
                    log::debug!(
                        "Found CALL instruction at 0x{:X} targeting 0x{:X}, manually relocating",
                        instr.ip(),
                        target_addr
                    );

                    // Generate new CALL instruction with correct displacement
                    let call_bytes = thunk::generate_call_rel32(
                        trampoline_instr_addr,
                        target_addr as usize,
                    );

                    relocated_bytes.extend_from_slice(&call_bytes);
                    original_offset += instr_len;
                    continue;
                }

            // Check if this is a conditional jump (Jcc)
            if let Some(target_addr) = disasm_instr.relative_branch_target() {
                // Check if it's a conditional jump (not unconditional JMP or CALL which we handle elsewhere)
                if instr.is_jcc_short_or_near() && !instr.is_jmp_short_or_near() {
                    // Check if jump target is within the stolen prolog (internal branch)
                    let is_internal = target_addr >= prolog_start && target_addr < prolog_end;

                    if is_internal {
                        log::debug!(
                            "Found internal Jcc at 0x{:X} targeting 0x{:X} (within prolog), copying unchanged",
                            instr.ip(),
                            target_addr
                        );

                        // Track this as an internal branch target
                        internal_branch_target = Some(target_addr);

                        // For internal branches, copy the instruction unchanged
                        // The relative offset is still valid within the copied prolog
                        relocated_bytes.extend_from_slice(instr_bytes);
                        original_offset += instr_len;
                        continue;
                    } else {
                        log::debug!(
                            "Found external Jcc at 0x{:X} targeting 0x{:X}, expanding to long form",
                            instr.ip(),
                            target_addr
                        );

                        // Extract condition code from original instruction
                        let condition = thunk::extract_jcc_condition(instr_bytes);

                        // Generate long-form conditional jump (6 bytes)
                        let jcc_bytes = thunk::generate_jcc_rel32(
                            trampoline_instr_addr,
                            target_addr as usize,
                            condition,
                        );

                        // CRITICAL: Check if size changed
                        if jcc_bytes.len() != instr_len {
                            // Check if we're inside an internal branch
                            if let Some(branch_target) = internal_branch_target
                                && instr.ip() < branch_target {
                                    log::error!(
                                        "Size change detected: instruction at 0x{:X} changed from {} to {} bytes, but is inside internal branch targeting 0x{:X}",
                                        instr.ip(),
                                        instr_len,
                                        jcc_bytes.len(),
                                        branch_target
                                    );
                                    return Err(DisasmError::UnsupportedInstruction(
                                        "Cannot hook: conditional jump size change would break internal branch".to_string()
                                    ));
                                }
                        }

                        relocated_bytes.extend_from_slice(&jcc_bytes);
                        original_offset += instr_len;
                        continue;
                    }
                }
            }

            // For all other instructions, use BlockEncoder for automatic relocation
            // This handles: regular instructions, RIP-relative memory operands, etc.
            let mut new_instr = *instr;
            new_instr.set_ip(trampoline_instr_addr as u64);

            let instr_array = [new_instr];
            let encoded = {
                let block = InstructionBlock::new(&instr_array, trampoline_instr_addr as u64);
                BlockEncoder::encode(
                    BITNESS,
                    block,
                    BlockEncoderOptions::NONE,
                )?
            };

            if encoded.code_buffer.is_empty() {
                return Err(DisasmError::EncodingError(
                    format!("BlockEncoder produced empty result for instruction at 0x{:X}", instr.ip())
                ));
            }

            log::trace!(
                "BlockEncoder relocated instruction from {} bytes to {} bytes",
                instr_len,
                encoded.code_buffer.len()
            );

            relocated_bytes.extend_from_slice(&encoded.code_buffer);
            original_offset += instr_len;
        }

        log::debug!(
            "Successfully relocated {} instructions: {} bytes -> {} bytes",
            instr_len,
            self.stolen_bytes_len,
            relocated_bytes.len()
        );

        // Log the relocated bytes for debugging
        log::trace!(
            "Original bytes: {:02X?}",
            self.stolen_bytes
        );
        log::trace!(
            "Relocated bytes: {:02X?}",
            &relocated_bytes
        );

        Ok(relocated_bytes)
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

    /// Returns true if any stolen instructions use RIP-relative addressing
    pub fn has_rip_relative(&self) -> bool {
        self.has_rip_relative
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
            log::trace!("Creating near(relative) jump");

            let mut instr = Instruction::with_branch(Code::Jmp_rel32_64, to_addr)?;
            instr.set_ip(from_addr);

            let mut encoder = Encoder::new(BITNESS);
            let encoded_len = encoder.encode(&instr, from_addr)?;

            let buffer = encoder.take_buffer();
            if buffer.len() != 5 {
                return Err(DisasmError::EncodingError(format!(
                    "Expected 5 bytes for near jump, got {} (encoded_len={})",
                    buffer.len(),
                    encoded_len
                )));
            }

            log::trace!(
                "Near(relative) jump created with distance {} bytes from: {:p} to: {:p}",
                distance,
                from,
                to
            );
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

            instr.set_ip(from_addr);

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
        log::trace!("Creating x86 near jump");
        let mut instr = Instruction::with_branch(Code::Jmp_rel32_32, to_addr)?;
        instr.set_ip(from_addr);

        let mut encoder = Encoder::new(BITNESS);
        let _result = encoder
            .encode(&instr, from_addr)
            .map_err(|e| DisasmError::EncodingError(format!("{:?}", e)))?;

        // if result != instr.len() {
        //     return Err(DisasmError::EncodingError(
        //         "Encoding size mismatch".to_string(),
        //     ));
        // }

        let buffer = encoder.take_buffer();
        if buffer.len() != 5 {
            return Err(DisasmError::EncodingError(format!(
                "Expected 5 bytes for x86 jump, got {}",
                buffer.len()
            )));
        }

        Ok(buffer)
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

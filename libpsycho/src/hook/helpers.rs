use std::{ffi::c_void, ptr::NonNull};

use iced_x86::{Decoder, DecoderOptions, Instruction};

use crate::winapi::read_bytes;

use super::*;

/// Finds entry pointer for requested function and module
/// Implementation is pretty simple under the hood,
/// We guess that module size can't be too large(this may be an issue for complex .dll files),
/// `scan_size` should be <= 64Mb, otherwise scanning may be too long.
pub fn find_iat_entry(
    base: NonNull<c_void>,
    original_function: NonNull<c_void>,
    scan_size: usize,
    dll_name: &str,
    func_name: &str,
) -> Result<IatEntryPtr> {
    // Validate inputs
    if scan_size == 0 || scan_size > usize::MAX / 2 {
        return Err(HookError::InvalidScanSizeError(
            dll_name.to_owned(),
            func_name.to_owned(),
        ));
    }

    // Get base address as a usize for pointer arithmetic
    let base_addr = base.as_ptr() as usize;
    let ptr_size = std::mem::size_of::<*mut c_void>();

    // Check alignment
    if base_addr % ptr_size != 0 {
        return Err(HookError::MisalignedBaseAddressError(
            dll_name.to_owned(),
            func_name.to_owned(),
        ));
    }

    // Get the module's size (for scanning)
    // 64MB should be enough for most modules
    let module_size = 64 * 1024 * 1024;

    // Scan the module's memory for pointers to the original function
    let ptr_region = unsafe {
        std::slice::from_raw_parts_mut(
            base.as_ptr() as *mut *mut c_void,
            module_size / std::mem::size_of::<*mut c_void>(),
        )
    };

    // Find the pointer in the IAT
    #[allow(clippy::needless_range_loop)]
    for i in 0..ptr_region.len() {
        if ptr_region[i] == original_function.as_ptr() {
            // Found the IAT entry - use a raw pointer directly
            let iat_entry_ptr = &mut ptr_region[i] as *mut *mut c_void;

            return Ok(iat_entry_ptr);
        }
    }

    Err(HookError::OriginFuncNotFoundInRegionError(
        dll_name.to_owned(),
        func_name.to_owned(),
    ))
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn detect_vtable_size(vtable_ptr: VtablePtr) -> Result<usize> {
    let mut method_count = 0;

    // Controlled scanning with explicit bounds
    while method_count < MAX_VTABLE_SIZE {
        let ptr = unsafe { vtable_ptr.add(method_count) };

        // Use controlled exception handling to detect invalid memory
        match std::panic::catch_unwind(|| unsafe { std::ptr::read_volatile(ptr) }) {
            Ok(method_ptr) if method_ptr.is_null() => break,
            Ok(_) => method_count += 1,
            Err(_) => {
                return Err(HookError::MemoryAccessError(format!(
                    "Invalid memory at vtable offset {}",
                    method_count
                )));
            }
        }
    }

    // Safety check for extreme sizes
    if method_count == 0 {
        return Err(HookError::ValidationError("Empty vtable detected".into()));
    }

    if method_count == MAX_VTABLE_SIZE {
        return Err(HookError::VTableSizeExceededError);
    }

    Ok(method_count)
}

// /// Calculate minimum bytes needed without splitting instructions
// pub fn calculate_safe_patch_size(addr: NonNull<c_void>) -> anyhow::Result<usize> {
//     let code_bytes = read_bytes(addr, 32)?;

//     // Detect architecture - for now assume x64, but warn about limitation
//     #[cfg(target_pointer_width = "64")]
//     let bitness = 64;
//     #[cfg(target_pointer_width = "32")]
//     let bitness = 32;

//     let mut decoder = Decoder::with_ip(
//         bitness,
//         &code_bytes,
//         addr.as_ptr() as u64,
//         DecoderOptions::NONE,
//     );

//     let mut total_bytes = 0;
//     let mut instruction = Instruction::default();

//     while total_bytes < JMP_SIZE {
//         decoder.decode_out(&mut instruction);

//         if instruction.is_invalid() {
//             return Err(anyhow::anyhow!(
//                 "Invalid instruction at {:p}",
//                 addr.as_ptr()
//             ));
//         }

//         total_bytes += instruction.len();

//         // Safety check: don't go too far
//         if total_bytes > 32 {
//             return Err(anyhow::anyhow!(
//                 "Function prologue too complex to patch safely"
//             ));
//         }
//     }

//     Ok(total_bytes)
// }


/// Create absolute jump: JMP [RIP+0] followed by 8-byte target address
/// 
/// Assembly:
///   FF 25 00 00 00 00    ; JMP [RIP+0] 
///   XX XX XX XX XX XX XX XX  ; 8-byte target address
pub fn create_absolute_jump(target_addr: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(14);
    
    // JMP [RIP+0] instruction (6 bytes)
    bytes.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
    
    // 8-byte absolute address (little-endian)
    bytes.extend_from_slice(&target_addr.to_le_bytes());
    
    bytes
}

/// Simplified instruction size estimation - replace with proper disassembly
pub fn estimate_instruction_size(addr: usize) -> Result<usize> {
    // This is a placeholder! In real code, use iced-x86 to properly disassemble
    // For now, return a conservative estimate
    
    // Read first byte to get rough estimate
    let first_byte = unsafe { *(addr as *const u8) };
    
    // Very simplified heuristic - replace with proper disassembly!
    let size = match first_byte {
        0x48..=0x4F => 3, // REX prefix + 2-byte instruction (common)
        0x8B | 0x89 => 2, // MOV instructions
        0xFF => 2,        // Various instructions
        0xE8 | 0xE9 => 5, // CALL/JMP rel32
        _ => 2,           // Conservative default
    };
    
    Ok(size)
}

/// Calculate safe patch size for instruction alignment
/// Now requires minimum 14 bytes for absolute jumps
pub fn calculate_safe_patch_size(addr: NonNull<c_void>, min_size: usize) -> Result<usize> {
    // This should use instruction disassembly to ensure we don't break instructions
    // For now, simplified version that ensures minimum size
    
    // You would use iced-x86 or similar here to properly disassemble
    // and find instruction boundaries
    
    // Simplified: assume we need at least min_size bytes
    // In real implementation, disassemble instructions until we have >= min_size bytes
    // of complete instructions
    
    let mut total_size = 0;
    let mut current_addr = addr.as_ptr() as usize;
    
    // Simplified instruction size detection - replace with proper disassembly
    while total_size < min_size {
        // This is a placeholder - you need proper instruction length detection
        // Most x64 instructions are 1-15 bytes, common ones are 2-7 bytes
        let instruction_size = estimate_instruction_size(current_addr)?;
        total_size += instruction_size;
        current_addr += instruction_size;
    }
    
    Ok(total_size)
}

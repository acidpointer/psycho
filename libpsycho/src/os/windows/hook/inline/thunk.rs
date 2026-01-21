#![allow(dead_code)]
//! x86 instruction generation utilities
//!
//! This module provides functions to generate specific x86 instructions
//! as byte sequences, similar to retour-rs's thunk system.

use std::mem;

/// Represents a relative jump instruction (JMP rel32)
#[repr(C, packed)]
struct JumpRel32 {
    opcode: u8,
    displacement: i32,
}

/// Represents a relative call instruction (CALL rel32)
#[repr(C, packed)]
struct CallRel32 {
    opcode: u8,
    displacement: i32,
}

/// Represents a conditional jump instruction (Jcc rel32)
#[repr(C, packed)]
struct JccRel32 {
    opcode0: u8,  // Always 0x0F
    opcode1: u8,  // 0x80 | condition
    displacement: i32,
}

/// Calculates the relative displacement for a branch instruction
///
/// # Arguments
/// * `source` - Address where the instruction will be located
/// * `destination` - Target address the instruction should jump to
/// * `instruction_size` - Size of the instruction in bytes
///
/// # Returns
/// The displacement as i32 (signed 32-bit offset)
fn calculate_displacement(source: usize, destination: usize, instruction_size: usize) -> i32 {
    let displacement = (destination as isize)
        .wrapping_sub(source as isize)
        .wrapping_sub(instruction_size as isize);

    // On x86 (32-bit), all addresses fit within 4GB, so displacement always fits in i32
    // On x86_64, we need to verify it's within ±2GB range
    #[cfg(target_arch = "x86_64")]
    {
        const MAX_DISPLACEMENT: isize = 0x7FFFFFFF;
        const MIN_DISPLACEMENT: isize = -0x80000000;
        assert!(
            displacement >= MIN_DISPLACEMENT && displacement <= MAX_DISPLACEMENT,
            "Displacement out of range: {:#x} (source: {:#x}, dest: {:#x})",
            displacement,
            source,
            destination
        );
    }

    displacement as i32
}

/// Generates a relative JMP instruction (5 bytes: E9 XX XX XX XX)
///
/// # Arguments
/// * `source` - Address where this JMP will be located
/// * `destination` - Target address to jump to
///
/// # Returns
/// Vec<u8> containing the JMP instruction bytes
pub fn generate_jmp_rel32(source: usize, destination: usize) -> Vec<u8> {
    const JMP_OPCODE: u8 = 0xE9;
    const INSTRUCTION_SIZE: usize = 5;

    let displacement = calculate_displacement(source, destination, INSTRUCTION_SIZE);

    let instruction = JumpRel32 {
        opcode: JMP_OPCODE,
        displacement,
    };

    unsafe {
        let bytes: [u8; 5] = mem::transmute(instruction);
        bytes.to_vec()
    }
}

/// Generates a relative CALL instruction (5 bytes: E8 XX XX XX XX)
///
/// # Arguments
/// * `source` - Address where this CALL will be located
/// * `destination` - Target address to call
///
/// # Returns
/// Vec<u8> containing the CALL instruction bytes
pub fn generate_call_rel32(source: usize, destination: usize) -> Vec<u8> {
    const CALL_OPCODE: u8 = 0xE8;
    const INSTRUCTION_SIZE: usize = 5;

    let displacement = calculate_displacement(source, destination, INSTRUCTION_SIZE);

    let instruction = CallRel32 {
        opcode: CALL_OPCODE,
        displacement,
    };

    unsafe {
        let bytes: [u8; 5] = mem::transmute(instruction);
        bytes.to_vec()
    }
}

/// Generates a conditional jump instruction in long form (6 bytes: 0F 8X XX XX XX XX)
///
/// # Arguments
/// * `source` - Address where this Jcc will be located
/// * `destination` - Target address to jump to if condition is met
/// * `condition` - The condition code (0-15, extracted from original instruction)
///
/// # Returns
/// Vec<u8> containing the conditional jump instruction bytes
///
/// # Condition Codes
/// - 0x0: JO  (overflow)
/// - 0x1: JNO (not overflow)
/// - 0x2: JB/JC/JNAE (below/carry)
/// - 0x3: JAE/JNB/JNC (above or equal/not below/not carry)
/// - 0x4: JE/JZ (equal/zero)
/// - 0x5: JNE/JNZ (not equal/not zero)
/// - 0x6: JBE/JNA (below or equal/not above)
/// - 0x7: JA/JNBE (above/not below or equal)
/// - 0x8: JS (sign)
/// - 0x9: JNS (not sign)
/// - 0xA: JP/JPE (parity/parity even)
/// - 0xB: JNP/JPO (not parity/parity odd)
/// - 0xC: JL/JNGE (less/not greater or equal)
/// - 0xD: JGE/JNL (greater or equal/not less)
/// - 0xE: JLE/JNG (less or equal/not greater)
/// - 0xF: JG/JNLE (greater/not less or equal)
pub fn generate_jcc_rel32(source: usize, destination: usize, condition: u8) -> Vec<u8> {
    const JCC_OPCODE0: u8 = 0x0F;
    const JCC_OPCODE1_BASE: u8 = 0x80;
    const INSTRUCTION_SIZE: usize = 6;

    assert!(condition <= 0x0F, "Invalid condition code: {:#x}", condition);

    let displacement = calculate_displacement(source, destination, INSTRUCTION_SIZE);

    let instruction = JccRel32 {
        opcode0: JCC_OPCODE0,
        opcode1: JCC_OPCODE1_BASE | condition,
        displacement,
    };

    unsafe {
        let bytes: [u8; 6] = mem::transmute(instruction);
        bytes.to_vec()
    }
}

/// Extracts the condition code from a conditional jump instruction
///
/// # Arguments
/// * `instruction_bytes` - The original instruction bytes
///
/// # Returns
/// The condition code (0-15)
pub fn extract_jcc_condition(instruction_bytes: &[u8]) -> u8 {
    // Find the primary opcode (skip 0x0F prefix for long jumps)
    let primary_opcode = instruction_bytes
        .iter()
        .find(|&&byte| byte != 0x0F)
        .expect("Failed to find primary opcode in Jcc instruction");

    // Extract condition: opcode & 0x0F
    // For example: 0x74 (JZ) -> 0x74 & 0x0F = 0x04
    // For long form: 0x84 (JZ long) -> 0x84 & 0x0F = 0x04
    primary_opcode & 0x0F
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jmp_rel32_generation() {
        // JMP from 0x1000 to 0x2000
        let bytes = generate_jmp_rel32(0x1000, 0x2000);
        assert_eq!(bytes.len(), 5);
        assert_eq!(bytes[0], 0xE9); // JMP opcode

        // Displacement should be: 0x2000 - 0x1000 - 5 = 0xFFB
        let displacement = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        assert_eq!(displacement, 0x0FFB);
    }

    #[test]
    fn test_call_rel32_generation() {
        // CALL from 0x1000 to 0x1500
        let bytes = generate_call_rel32(0x1000, 0x1500);
        assert_eq!(bytes.len(), 5);
        assert_eq!(bytes[0], 0xE8); // CALL opcode

        // Displacement should be: 0x1500 - 0x1000 - 5 = 0x4FB
        let displacement = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        assert_eq!(displacement, 0x04FB);
    }

    #[test]
    fn test_jcc_rel32_generation() {
        // JNZ (condition 0x5) from 0x1000 to 0x2000
        let bytes = generate_jcc_rel32(0x1000, 0x2000, 0x5);
        assert_eq!(bytes.len(), 6);
        assert_eq!(bytes[0], 0x0F); // Jcc prefix
        assert_eq!(bytes[1], 0x85); // JNZ long form (0x80 | 0x5)

        // Displacement should be: 0x2000 - 0x1000 - 6 = 0xFFA
        let displacement = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        assert_eq!(displacement, 0x0FFA);
    }

    #[test]
    fn test_extract_jcc_condition() {
        // Short JNZ: 75 XX
        let short_jnz = vec![0x75, 0x10];
        assert_eq!(extract_jcc_condition(&short_jnz), 0x5);

        // Long JNZ: 0F 85 XX XX XX XX
        let long_jnz = vec![0x0F, 0x85, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(extract_jcc_condition(&long_jnz), 0x5);

        // JZ: 74 XX
        let jz = vec![0x74, 0x20];
        assert_eq!(extract_jcc_condition(&jz), 0x4);
    }

    #[test]
    fn test_backward_jump() {
        // JMP from 0x2000 to 0x1000 (backward)
        let bytes = generate_jmp_rel32(0x2000, 0x1000);
        assert_eq!(bytes[0], 0xE9);

        // Displacement should be negative: 0x1000 - 0x2000 - 5 = -0x1005
        let displacement = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        assert_eq!(displacement, -0x1005);
    }
}

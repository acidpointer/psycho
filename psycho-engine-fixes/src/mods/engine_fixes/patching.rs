//! Exact-fingerprint helpers for fixed FalloutNV 1.4.0.525 patch sites.

use std::{ffi::c_void, slice};

use anyhow::{Context, ensure};

use libpsycho::os::windows::winapi::patch_bytes;

pub(super) unsafe fn verify_bytes(address: usize, expected: &[u8]) -> anyhow::Result<()> {
    let observed = unsafe { slice::from_raw_parts(address as *const u8, expected.len()) };
    ensure!(
        observed == expected,
        "fingerprint mismatch at 0x{address:08X}: expected {:02X?}, observed {:02X?}",
        expected,
        observed
    );
    Ok(())
}

pub(super) unsafe fn relative_call_target(address: usize) -> anyhow::Result<usize> {
    let observed = unsafe { slice::from_raw_parts(address as *const u8, 5) };
    let [opcode, byte_0, byte_1, byte_2, byte_3] = observed else {
        anyhow::bail!("could not read direct CALL at 0x{address:08X}");
    };
    ensure!(
        *opcode == 0xE8,
        "expected direct CALL at 0x{address:08X}, observed {:02X?}",
        observed
    );
    let displacement = i32::from_le_bytes([*byte_0, *byte_1, *byte_2, *byte_3]);
    Ok((address + 5).wrapping_add_signed(displacement as isize))
}

pub(super) unsafe fn redirect_relative_call(
    address: usize,
    target: *mut c_void,
) -> anyhow::Result<usize> {
    let observed_slice = unsafe { slice::from_raw_parts(address as *const u8, 5) };
    let [opcode, byte_0, byte_1, byte_2, byte_3] = observed_slice else {
        anyhow::bail!("could not read direct CALL at 0x{address:08X}");
    };
    let observed = [*opcode, *byte_0, *byte_1, *byte_2, *byte_3];
    ensure!(
        observed[0] == 0xE8,
        "expected direct CALL at 0x{address:08X}, observed {:02X?}",
        observed
    );
    let displacement = i32::from_le_bytes([*byte_0, *byte_1, *byte_2, *byte_3]);
    let previous = (address + 5).wrapping_add_signed(displacement as isize);

    let next_displacement = (target as usize).wrapping_sub(address + 5) as i32;
    let mut replacement = [0u8; 5];
    replacement[0] = 0xE8;
    replacement[1..].copy_from_slice(&next_displacement.to_le_bytes());
    unsafe { verify_bytes(address, &observed) }?;
    unsafe { patch_bytes(address as *mut c_void, &replacement) }
        .with_context(|| format!("redirect relative call at 0x{address:08X}"))?;
    Ok(previous)
}

pub(super) unsafe fn replace_block(
    address: usize,
    expected: &[u8],
    replacement: &[u8],
) -> anyhow::Result<()> {
    ensure!(expected.len() == replacement.len(), "patch length mismatch");
    unsafe { verify_bytes(address, expected) }?;
    unsafe { patch_bytes(address as *mut c_void, replacement) }
        .with_context(|| format!("patch instruction block at 0x{address:08X}"))?;
    Ok(())
}

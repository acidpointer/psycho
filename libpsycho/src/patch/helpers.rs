use std::{ffi::c_void, ptr::NonNull};

pub use super::*;

/// Validates that a branch target is within range
pub fn validate_branch_range(source: NonNull<c_void>, target: NonNull<c_void>) -> Result<()> {
    let source_addr = source.as_ptr() as usize;
    let target_addr = target.as_ptr() as usize;

    // Calculate distance between addresses
    let distance = target_addr.abs_diff(source_addr);

    // Maximum allowed distance is 2^31 - 1 (±2GB range for 32-bit relative offset)
    if distance > 0x7FFF_FFFF {
        Err(PatchError::RangeTooLarge)
    } else {
        Ok(())
    }
}

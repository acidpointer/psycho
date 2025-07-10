#![allow(
    dead_code,
    unused_variables,
    unreachable_code,
    unused_imports,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::needless_return
)]

use std::{ffi::c_void, path::Path, ptr::NonNull};

#[cfg(target_os = "windows")]
use windows::core::{PCSTR, PCWSTR};

use super::Result;
use crate::winapi::{
    errors::WindowsError, virtual_protect_execute_readwrite, virtual_protect_restore,
};

/// Naive linear search for a needle in a haystack with wildcards
pub fn scan(haystack: &[u8], needle: &[Option<u8>]) -> Option<usize> {
    if haystack.is_empty() {
        return None;
    }

    for i in 0..haystack.len() - needle.len() {
        let mut found = true;
        for j in 0..needle.len() {
            if let Some(byte) = needle[j] {
                if byte != haystack[i + j] {
                    found = false;
                    break;
                }
            }
        }
        if found {
            return Some(i);
        }
    }
    None
}

/// Converts a string of hex characters into a byte pattern with wildcards.
/// ? is the character used for wildcards.
/// Hex characters don't have to be prefixed with 0x
pub fn to_pattern(str: &str) -> Vec<Option<u8>> {
    let mut vec = Vec::new();
    for substr in str.split(" ") {
        if substr == "?" {
            vec.push(None);
        } else {
            vec.push(Some(
                u8::from_str_radix(substr, 16).expect("invalid hex string in pattern string"),
            ));
        }
    }
    vec
}

/// Win32 memes. Use with caution.
pub fn vec_u16_to_u8(vec_u16: &[u16]) -> Vec<u8> {
    unsafe { vec_u16.align_to::<u8>().1.to_vec() }
}

/// Validates memory alignment for the given address
pub fn validate_alignment(address: NonNull<c_void>, alignment: usize) -> Result<()> {
    let ptr = address.as_ptr() as usize;
    if ptr % alignment != 0 {
        Err(WindowsError::UnalignedMemoryAccess(ptr, alignment))
    } else {
        Ok(())
    }
}

/// Validates range of memory (raw pointer + it's size)
/// Checks if range of memory is commited and sise is okay
pub fn validate_memory_range(address: NonNull<c_void>, size: usize) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use super::query_memory;
        use windows::Win32::System::Memory::MEM_COMMIT;

        if size == 0 {
            return Err(WindowsError::InvalidSize);
        }

        let info = query_memory(address)?;

        // Check if memory is committed
        if info.state != MEM_COMMIT.0 {
            return Err(WindowsError::MemoryNotCommitted(address.as_ptr() as usize));
        }

        let base_address = info.base_address as usize;
        let region_size = info.base_address as usize;
        let end_address = base_address
            .checked_add(region_size)
            .ok_or_else(|| WindowsError::InvalidMemoryRange(base_address, region_size))?;

        let target_end = (address.as_ptr() as usize)
            .checked_add(size)
            .ok_or_else(|| WindowsError::InvalidMemoryRange(address.as_ptr() as usize, size))?;

        if target_end > end_address {
            return Err(WindowsError::InvalidMemoryRange(
                address.as_ptr() as usize,
                size,
            ));
        } else {
            return Ok(());
        }

        return Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    unimplemented!("validate_memory_range supported only for Windows target")
}



/// Safely writes bytes to memory
pub fn write_bytes(address: NonNull<c_void>, buffer: &[u8]) -> Result<()> {
    if buffer.is_empty() {
        return Ok(());
    }

    validate_memory_range(address, buffer.len())?;

    let old_protect = virtual_protect_execute_readwrite(address.as_ptr(), Some(buffer.len()))?;

    unsafe {
        std::ptr::copy_nonoverlapping(buffer.as_ptr(), address.as_ptr() as *mut u8, buffer.len());
    }

    virtual_protect_restore(address.as_ptr(), old_protect, Some(buffer.len()))?;

    Ok(())
}

/// Safely reads bytes from memory
pub fn read_bytes(address: NonNull<c_void>, size: usize) -> Result<Vec<u8>> {
    if size == 0 {
        return Ok(Vec::new());
    }

    validate_memory_range(address, size)?;

    let mut buffer = vec![0u8; size];

    unsafe {
        std::ptr::copy_nonoverlapping(address.as_ptr() as *const u8, buffer.as_mut_ptr(), size);
    }

    Ok(buffer)
}

//! Windows memory management utilities
//!
//! This module provides safe memory operations for function hooking,
//! including executable memory allocation, memory protection changes,
//! and safe memory read/write operations using the winapi wrapper.

use libc::c_void;
use thiserror::Error;
use windows::Win32::System::Memory::{
    MEM_COMMIT, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};

use crate::os::windows::winapi::{virtual_query, with_virtual_protect};

use super::winapi::{WinapiError, flush_instructions_cache};

/// Memory state constant for `query_memory` validation
pub const MEMORY_STATE_COMMIT: u32 = MEM_COMMIT.0;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("Invalid memory range: base=0x{0:X}, size={1}")]
    InvalidMemoryRange(usize, usize),

    #[error("Memory allocation failed")]
    AllocationFailed,

    #[error("Memory not committed at address 0x{0:X}")]
    MemoryNotCommitted(usize),

    #[error("Target memory is not accessible: {0:X}")]
    InaccessibleMemory(usize),

    #[error("Target memory is not executable: {0:X}")]
    NonExecutableMemory(usize),

    #[error("WinAPI error: {0}")]
    WinapiError(#[from] WinapiError),
}

pub type MemoryResult<T> = std::result::Result<T, MemoryError>;

/// Memory protection information for restoration
#[derive(Debug, Clone, Copy)]
pub struct MemoryProtection {
    pub old_protect: PAGE_PROTECTION_FLAGS,
}

/// Validate that a memory range is accessible
pub fn validate_memory_range(address: *const c_void, size: usize) -> MemoryResult<()> {
    log::trace!("Validating memory range: {:p}, size: {}", address, size);

    let info = virtual_query(address as *mut c_void)?;
    log::debug!(
        "Memory info: base={:p}, size={}, state=0x{:X}, protect={}",
        info.base_address,
        info.region_size,
        info.state,
        info.protect.0
    );

    if info.state != MEMORY_STATE_COMMIT {
        log::error!(
            "Memory not committed at {:p}, state=0x{:X}",
            address,
            info.state
        );
        return Err(MemoryError::MemoryNotCommitted(address as usize));
    }

    let start = address as usize;
    let end = start
        .checked_add(size)
        .ok_or_else(|| MemoryError::InvalidMemoryRange(start, size))?;
    let region_start = info.base_address as usize;
    let region_end = region_start
        .checked_add(info.region_size)
        .ok_or_else(|| MemoryError::InvalidMemoryRange(region_start, info.region_size))?;

    if start < region_start || end > region_end {
        log::error!(
            "Memory range validation failed: range 0x{:X}-0x{:X} not within region 0x{:X}-0x{:X}",
            start,
            end,
            region_start,
            region_end
        );
        return Err(MemoryError::InvalidMemoryRange(start, size));
    }

    log::trace!("Memory range validation successful");
    Ok(())
}

/// Read bytes from memory region
/// # Arguments:
/// - `address` - memory address, reading start point
/// - `size`    - memory size to read in bytes
///
/// # Safety
///
/// Memory range validated with `validate_memory_range`
pub fn read_bytes(address: *const c_void, size: usize) -> MemoryResult<Vec<u8>> {
    log::debug!("Reading {} bytes from {:p}", size, address);

    if size == 0 {
        return Ok(Vec::new());
    }

    validate_memory_range(address, size)?;

    let mut buffer = vec![0u8; size];
    unsafe {
        std::ptr::copy_nonoverlapping(address as *const u8, buffer.as_mut_ptr(), size);
    }

    log::trace!(
        "Read bytes: {:02x?}",
        if buffer.len() <= 16 {
            buffer.as_slice()
        } else {
            &buffer[..16]
        }
    );

    log::debug!("Successfully read {} bytes", size);
    Ok(buffer)
}

/// Write bytes to memory by address
/// # Arguments:
/// - `address` - memory address, writing start point
/// - `data`    - slice of bytes which will be written
///
///  # Safety
/// Input `data` should not be empty
///
/// Memory range validated with `validate_memory_range`
///
/// Calls of `VirtualProtect` additionally protected by `with_virtual_protect`
pub unsafe fn write_bytes(address: *mut c_void, data: &[u8]) -> MemoryResult<()> {
    log::debug!("Writing {} bytes to {:p}", data.len(), address);

    if data.is_empty() {
        return Ok(());
    }

    validate_memory_range(address, data.len())?;

    unsafe {
        with_virtual_protect(address, PAGE_READWRITE, data.len(), || {
            std::ptr::copy_nonoverlapping(data.as_ptr(), address as *mut u8, data.len());

            log::trace!(
                "Writing data: {:02x?}",
                if data.len() <= 16 { data } else { &data[..16] }
            );
        })?;
    }

    flush_instructions_cache(address, data.len())?;

    log::debug!("Successfully wrote {} bytes to memory", data.len());

    Ok(())
}

/// Validates memory behind pointer and return protection flag and region size
/// # Arguments:
/// - `ptr` - Pointer to memory we want to check
pub fn validate_memory_access(ptr: *mut c_void) -> MemoryResult<(PAGE_PROTECTION_FLAGS, usize)> {
    // First, we need to understand what memory behind pointer
    let mem_info = virtual_query(ptr)?;

    // Next, we check if memory is commited.
    // If not - it's obvious error, we cant work with not commited memory.
    if mem_info.state != MEMORY_STATE_COMMIT {
        return Err(MemoryError::InaccessibleMemory(ptr as usize));
    }

    // Fine, now let's check memory protection flag
    let protect = mem_info.protect;

    // We need to check if memory is executable
    let is_executable = matches!(
        protect,
        PAGE_EXECUTE | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_WRITECOPY
    );

    // If memory is not executable, we return error.
    // Functions can be located only in executable memory.
    if !is_executable {
        return Err(MemoryError::NonExecutableMemory(ptr as usize));
    }

    Ok((protect, mem_info.region_size))
}

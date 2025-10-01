//! Windows memory management utilities for hooking
//!
//! This module provides safe memory operations for function hooking,
//! including executable memory allocation, memory protection changes,
//! and safe memory read/write operations using the winapi wrapper.

use libc::c_void;
use thiserror::Error;

use crate::os::windows::winapi::virtual_query;

use super::winapi::{
    PageProtectionFlags, WinapiError,
    flush_instructions_cache, virtual_protect,
};

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("Invalid memory range: base=0x{0:X}, size={1}")]
    InvalidMemoryRange(usize, usize),

    #[error("Memory allocation failed")]
    AllocationFailed,

    #[error("Memory not committed at address 0x{0:X}")]
    MemoryNotCommitted(usize),

    #[error("WinAPI error: {0}")]
    WinapiError(#[from] WinapiError),
}

pub type MemoryResult<T> = std::result::Result<T, MemoryError>;

/// Memory protection information for restoration
#[derive(Debug, Clone, Copy)]
pub struct MemoryProtection {
    pub old_protect: PageProtectionFlags,
}


/// Validate that a memory range is accessible
pub fn validate_memory_range(address: *const c_void, size: usize) -> MemoryResult<()> {
    log::trace!("Validating memory range: {:p}, size: {}", address, size);

    let info = virtual_query(address as *mut c_void)?;
    log::debug!("Memory info: base={:p}, size={}, state=0x{:X}, protect={}",
           info.base_address, info.region_size, info.state, info.protect);

    if info.state != super::winapi::MEMORY_STATE_COMMIT {
        log::error!("Memory not committed at {:p}, state=0x{:X}", address, info.state);
        return Err(MemoryError::MemoryNotCommitted(address as usize));
    }

    let start = address as usize;
    let end = start.checked_add(size)
        .ok_or_else(|| MemoryError::InvalidMemoryRange(start, size))?;
    let region_start = info.base_address as usize;
    let region_end = region_start.checked_add(info.region_size)
        .ok_or_else(|| MemoryError::InvalidMemoryRange(region_start, info.region_size))?;

    if start < region_start || end > region_end {
        log::error!("Memory range validation failed: range 0x{:X}-0x{:X} not within region 0x{:X}-0x{:X}",
               start, end, region_start, region_end);
        return Err(MemoryError::InvalidMemoryRange(start, size));
    }

    log::trace!("Memory range validation successful");
    Ok(())
}

/// Safely read bytes from memory
pub fn read_bytes(address: *const c_void, size: usize) -> MemoryResult<Vec<u8>> {
    log::debug!("Reading {} bytes from {:p}", size, address);

    if size == 0 {
        log::trace!("Zero-size read, returning empty buffer");
        return Ok(Vec::new());
    }

    validate_memory_range(address, size)?;

    let mut buffer = vec![0u8; size];
    unsafe {
        std::ptr::copy_nonoverlapping(address as *const u8, buffer.as_mut_ptr(), size);
    }

    log::trace!("Read bytes: {:02x?}",
           if buffer.len() <= 16 { buffer.as_slice() } else { &buffer[..16] });
    log::debug!("Successfully read {} bytes", size);
    Ok(buffer)
}

/// Safely write bytes to memory with temporary protection change
pub fn write_bytes(address: *mut c_void, data: &[u8]) -> MemoryResult<()> {
    log::debug!("Writing {} bytes to {:p}", data.len(), address);

    if data.is_empty() {
        log::trace!("Zero-size write, nothing to do");
        return Ok(());
    }

    validate_memory_range(address, data.len())?;

    log::debug!("Changing memory protection to allow writing");
    let old_protect = virtual_protect(
        address,
        PageProtectionFlags::PageReadwrite,
        data.len(),
    )?;
    log::trace!("Old protection: {:?}", old_protect);

    if let Err(e) = validate_memory_range(address, data.len()) {
        log::warn!("Memory validation failed after protection change, restoring protection");
        virtual_protect(address, old_protect, data.len())?;
        return Err(e);
    }

    log::trace!("Writing data: {:02x?}",
           if data.len() <= 16 { data } else { &data[..16] });
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), address as *mut u8, data.len());
    }

    log::debug!("Restoring memory protection");
    virtual_protect(address, old_protect, data.len())?;

    log::debug!("Flushing instruction cache");
    flush_instructions_cache(address, data.len())?;

    log::debug!("Successfully wrote {} bytes to memory", data.len());
    Ok(())
}

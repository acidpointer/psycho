//! Windows memory management utilities for hooking
//!
//! This module provides safe memory operations for function hooking,
//! including executable memory allocation, memory protection changes,
//! and safe memory read/write operations using the winapi wrapper.

use std::{ffi::c_void, ptr::NonNull};
use thiserror::Error;
use log::{debug, info, warn, error, trace};

use super::winapi::{
    AllocationType, FreeType, PageProtectionFlags, WinapiError,
    flush_instructions_cache, query_memory, virtual_alloc, virtual_free, virtual_protect,
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

/// Represents an allocated executable memory region for trampolines
#[derive(Debug)]
pub struct ExecutableMemory {
    ptr: NonNull<c_void>,
    size: usize,
}

impl ExecutableMemory {
    /// Allocate executable memory near the target address for trampolines
    ///
    /// This attempts to allocate within ±2GB of the target for 32-bit relative jumps
    pub fn allocate_near(target: *const c_void, size: usize) -> MemoryResult<Self> {
        debug!("Allocating executable memory: size={}, target={:p}", size, target);

        let page_size = 4096;
        let aligned_size = (size + page_size - 1) & !(page_size - 1);
        trace!("Aligned size: {} -> {}", size, aligned_size);

        let mut allocation = None;

        if let Some(near_addr) = calculate_allocation_address(target as usize, aligned_size) {
            debug!("Attempting near allocation at 0x{:X}", near_addr);
            let result = virtual_alloc(
                Some(near_addr as *const c_void),
                aligned_size,
                AllocationType::CommitReserve,
                PageProtectionFlags::PageExecuteReadWrite,
            );

            if let Ok(ptr) = result {
                info!("Near allocation succeeded at {:p}", ptr);
                allocation = Some(ptr);
            } else {
                debug!("Near allocation failed, will use fallback");
            }
        } else {
            debug!("No suitable near address found, using fallback");
        }

        let ptr = match allocation {
            Some(ptr) => ptr,
            None => {
                debug!("Allocating executable memory anywhere");
                virtual_alloc(
                    None,
                    aligned_size,
                    AllocationType::CommitReserve,
                    PageProtectionFlags::PageExecuteReadWrite,
                )?
            }
        };

        let memory = Self {
            ptr: NonNull::new(ptr).ok_or(MemoryError::AllocationFailed)?,
            size: aligned_size,
        };

        info!("Allocated executable memory at {:p}, size: {}", memory.as_ptr(), memory.size);
        Ok(memory)
    }

    /// Get the memory address
    pub fn as_ptr(&self) -> *mut c_void {
        self.ptr.as_ptr()
    }

    /// Get the size of the allocated memory
    pub fn size(&self) -> usize {
        self.size
    }

    /// Write data to the allocated memory
    pub fn write_bytes(&self, offset: usize, data: &[u8]) -> MemoryResult<()> {
        debug!("Writing {} bytes to executable memory at offset {}", data.len(), offset);

        if offset + data.len() > self.size {
            error!("Write would exceed memory bounds: offset={}, len={}, size={}",
                   offset, data.len(), self.size);
            return Err(MemoryError::InvalidMemoryRange(offset, data.len()));
        }

        let dest = unsafe { self.ptr.as_ptr().add(offset) };
        trace!("Writing to {:p}: {:02x?}", dest,
               if data.len() <= 16 { data } else { &data[..16] });

        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), dest as *mut u8, data.len());
        }

        flush_instructions_cache(dest, data.len())?;
        debug!("Successfully wrote {} bytes to executable memory", data.len());
        Ok(())
    }
}

impl Drop for ExecutableMemory {
    fn drop(&mut self) {
        debug!("Freeing executable memory at {:p}, size: {}", self.as_ptr(), self.size);
        if let Err(e) = virtual_free(self.ptr.as_ptr(), 0, FreeType::Release) {
            warn!("Failed to free executable memory: {}", e);
        } else {
            trace!("Successfully freed executable memory");
        }
    }
}

/// Validate that a memory range is accessible
pub fn validate_memory_range(address: *const c_void, size: usize) -> MemoryResult<()> {
    trace!("Validating memory range: {:p}, size: {}", address, size);

    let info = query_memory(address as *mut c_void)?;
    debug!("Memory info: base={:p}, size={}, state=0x{:X}, protect=0x{:X}",
           info.base_address, info.region_size, info.state, info.protect);

    if info.state != super::winapi::MEMORY_STATE_COMMIT {
        error!("Memory not committed at {:p}, state=0x{:X}", address, info.state);
        return Err(MemoryError::MemoryNotCommitted(address as usize));
    }

    let start = address as usize;
    let end = start.checked_add(size)
        .ok_or_else(|| MemoryError::InvalidMemoryRange(start, size))?;
    let region_start = info.base_address as usize;
    let region_end = region_start.checked_add(info.region_size)
        .ok_or_else(|| MemoryError::InvalidMemoryRange(region_start, info.region_size))?;

    if start < region_start || end > region_end {
        error!("Memory range validation failed: range 0x{:X}-0x{:X} not within region 0x{:X}-0x{:X}",
               start, end, region_start, region_end);
        return Err(MemoryError::InvalidMemoryRange(start, size));
    }

    trace!("Memory range validation successful");
    Ok(())
}

/// Safely read bytes from memory
pub fn read_bytes(address: *const c_void, size: usize) -> MemoryResult<Vec<u8>> {
    debug!("Reading {} bytes from {:p}", size, address);

    if size == 0 {
        trace!("Zero-size read, returning empty buffer");
        return Ok(Vec::new());
    }

    validate_memory_range(address, size)?;

    let mut buffer = vec![0u8; size];
    unsafe {
        std::ptr::copy_nonoverlapping(address as *const u8, buffer.as_mut_ptr(), size);
    }

    trace!("Read bytes: {:02x?}",
           if buffer.len() <= 16 { buffer.as_slice() } else { &buffer[..16] });
    debug!("Successfully read {} bytes", size);
    Ok(buffer)
}

/// Safely write bytes to memory with temporary protection change
pub fn write_bytes(address: *mut c_void, data: &[u8]) -> MemoryResult<()> {
    debug!("Writing {} bytes to {:p}", data.len(), address);

    if data.is_empty() {
        trace!("Zero-size write, nothing to do");
        return Ok(());
    }

    validate_memory_range(address, data.len())?;

    debug!("Changing memory protection to allow writing");
    let old_protect = virtual_protect(
        address,
        PageProtectionFlags::PageReadwrite,
        data.len(),
    )?;
    trace!("Old protection: {:?}", old_protect);

    if let Err(e) = validate_memory_range(address, data.len()) {
        warn!("Memory validation failed after protection change, restoring protection");
        virtual_protect(address, old_protect, data.len())?;
        return Err(e);
    }

    trace!("Writing data: {:02x?}",
           if data.len() <= 16 { data } else { &data[..16] });
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), address as *mut u8, data.len());
    }

    debug!("Restoring memory protection");
    virtual_protect(address, old_protect, data.len())?;

    debug!("Flushing instruction cache");
    flush_instructions_cache(address, data.len())?;

    debug!("Successfully wrote {} bytes to memory", data.len());
    Ok(())
}

/// Change memory protection and return the old protection
pub fn change_memory_protection(
    address: *mut c_void,
    size: usize,
    new_protect: PageProtectionFlags,
) -> MemoryResult<MemoryProtection> {
    debug!("Changing memory protection: {:p}, size={}, new_protect={:?}",
           address, size, new_protect);

    let old_protect = virtual_protect(address, new_protect, size)?;

    debug!("Memory protection changed: old={:?}, new={:?}",
           old_protect, new_protect);
    Ok(MemoryProtection { old_protect })
}

/// Restore memory protection
pub fn restore_memory_protection(
    address: *mut c_void,
    size: usize,
    protection: MemoryProtection,
) -> MemoryResult<()> {
    debug!("Restoring memory protection: {:p}, size={}, protect={:?}",
           address, size, protection.old_protect);

    virtual_protect(address, protection.old_protect, size)?;

    trace!("Memory protection restored successfully");
    Ok(())
}

/// Calculate a good allocation address near the target for relative jumps
fn calculate_allocation_address(target: usize, size: usize) -> Option<usize> {
    trace!("Calculating allocation address near 0x{:X}, size={}", target, size);

    const MAX_DISPLACEMENT: usize = 0x7FFF_0000;

    let lower_bound = target.saturating_sub(MAX_DISPLACEMENT);
    let upper_bound = target.saturating_add(MAX_DISPLACEMENT);

    debug!("Allocation bounds: 0x{:X} - 0x{:X}", lower_bound, upper_bound);

    let page_size = 4096;
    let aligned_lower = (lower_bound + page_size - 1) & !(page_size - 1);

    let offsets = [0x1000, 0x10000, 0x100000, 0x1000000, 0x10000000];

    for &offset in &offsets {
        for direction in [-1isize, 1isize] {
            let candidate = target.wrapping_add((offset as isize * direction) as usize);

            if candidate >= aligned_lower &&
               candidate.saturating_add(size) <= upper_bound &&
               candidate != 0 {
                trace!("Found suitable allocation address: 0x{:X}", candidate);
                return Some(candidate);
            }
        }
    }

    debug!("No suitable allocation address found near target");
    None
}
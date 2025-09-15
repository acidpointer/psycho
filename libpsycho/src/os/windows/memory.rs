//! Windows memory management utilities for hooking
//!
//! This module provides safe memory operations for function hooking,
//! including executable memory allocation, memory protection changes,
//! and safe memory read/write operations using the winapi wrapper.

use std::{ffi::c_void, ptr::NonNull};
use thiserror::Error;

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
        // Round up to page size (4KB on Windows)
        let page_size = 4096;
        let aligned_size = (size + page_size - 1) & !(page_size - 1);

        // Try to allocate within ±2GB of target for relative jumps
        let mut allocation = None;

        if let Some(near_addr) = calculate_allocation_address(target as usize, aligned_size) {
            let result = virtual_alloc(
                Some(near_addr as *const c_void),
                aligned_size,
                AllocationType::CommitReserve,
                PageProtectionFlags::PageExecuteReadWrite,
            );

            if let Ok(ptr) = result {
                allocation = Some(ptr);
            }
        }

        // Fallback: allocate anywhere
        let ptr = match allocation {
            Some(ptr) => ptr,
            None => virtual_alloc(
                None,
                aligned_size,
                AllocationType::CommitReserve,
                PageProtectionFlags::PageExecuteReadWrite,
            )?,
        };

        Ok(Self {
            ptr: NonNull::new(ptr).ok_or(MemoryError::AllocationFailed)?,
            size: aligned_size,
        })
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
        if offset + data.len() > self.size {
            return Err(MemoryError::InvalidMemoryRange(offset, data.len()));
        }

        let dest = unsafe { self.ptr.as_ptr().add(offset) };
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), dest as *mut u8, data.len());
        }

        // Flush instruction cache
        flush_instructions_cache(dest, data.len())?;

        Ok(())
    }
}

impl Drop for ExecutableMemory {
    fn drop(&mut self) {
        // Best effort cleanup - ignore errors in drop
        let _ = virtual_free(self.ptr.as_ptr(), 0, FreeType::Release);
    }
}

/// Validate that a memory range is accessible
pub fn validate_memory_range(address: *const c_void, size: usize) -> MemoryResult<()> {
    let info = query_memory(address as *mut c_void)?;

    // Check if memory is committed
    if info.state != super::winapi::MEMORY_STATE_COMMIT {
        return Err(MemoryError::MemoryNotCommitted(address as usize));
    }

    // Check if the entire range is within the queried region
    let start = address as usize;
    let end = start.checked_add(size)
        .ok_or_else(|| MemoryError::InvalidMemoryRange(start, size))?;
    let region_start = info.base_address as usize;
    let region_end = region_start.checked_add(info.region_size)
        .ok_or_else(|| MemoryError::InvalidMemoryRange(region_start, info.region_size))?;

    if start < region_start || end > region_end {
        return Err(MemoryError::InvalidMemoryRange(start, size));
    }

    Ok(())
}

/// Safely read bytes from memory
pub fn read_bytes(address: *const c_void, size: usize) -> MemoryResult<Vec<u8>> {
    if size == 0 {
        return Ok(Vec::new());
    }

    validate_memory_range(address, size)?;

    let mut buffer = vec![0u8; size];
    unsafe {
        std::ptr::copy_nonoverlapping(address as *const u8, buffer.as_mut_ptr(), size);
    }

    Ok(buffer)
}

/// Safely write bytes to memory with temporary protection change
pub fn write_bytes(address: *mut c_void, data: &[u8]) -> MemoryResult<()> {
    if data.is_empty() {
        return Ok(());
    }

    validate_memory_range(address, data.len())?;

    // Change protection to allow writing
    let old_protect = virtual_protect(
        address,
        PageProtectionFlags::PageReadwrite,
        data.len(),
    )?;

    // Write the data
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), address as *mut u8, data.len());
    }

    // Restore original protection
    virtual_protect(address, old_protect, data.len())?;

    // Flush instruction cache
    flush_instructions_cache(address, data.len())?;

    Ok(())
}

/// Change memory protection and return the old protection
pub fn change_memory_protection(
    address: *mut c_void,
    size: usize,
    new_protect: PageProtectionFlags,
) -> MemoryResult<MemoryProtection> {
    let old_protect = virtual_protect(address, new_protect, size)?;
    Ok(MemoryProtection { old_protect })
}

/// Restore memory protection
pub fn restore_memory_protection(
    address: *mut c_void,
    size: usize,
    protection: MemoryProtection,
) -> MemoryResult<()> {
    virtual_protect(address, protection.old_protect, size)?;
    Ok(())
}

/// Calculate a good allocation address near the target for relative jumps
fn calculate_allocation_address(target: usize, size: usize) -> Option<usize> {
    // Try to allocate within ±2GB for relative jumps (32-bit displacement)
    const MAX_DISPLACEMENT: usize = 0x7FFF_0000; // 2GB - small margin

    // Calculate bounds
    let lower_bound = target.saturating_sub(MAX_DISPLACEMENT);
    let upper_bound = target.saturating_add(MAX_DISPLACEMENT);

    // Align to page boundaries
    let page_size = 4096;
    let aligned_lower = (lower_bound + page_size - 1) & !(page_size - 1);

    // Try various offsets from the target
    let offsets = [
        0x1000,      // 4KB
        0x10000,     // 64KB
        0x100000,    // 1MB
        0x1000000,   // 16MB
        0x10000000,  // 256MB
    ];

    for &offset in &offsets {
        // Try both directions
        for direction in [-1isize, 1isize] {
            let candidate = target.wrapping_add((offset as isize * direction) as usize);

            if candidate >= aligned_lower &&
               candidate + size <= upper_bound &&
               candidate != 0 {
                return Some(candidate);
            }
        }
    }

    None
}
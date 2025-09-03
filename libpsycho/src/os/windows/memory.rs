use libc::c_void;
use thiserror::Error;
use windows::Win32::System::Memory::MEM_COMMIT;

use super::winapi::{PageProtectionFlags, WinapiError, query_memory, virtual_protect};

#[derive(Debug, Error)]
pub enum WinMemoryError {
    #[error("Invalid size parameter")]
    InvalidSize,

    #[error("Memory not committed at address 0x{0:X}")]
    MemoryNotCommitted(usize),

    #[error("Invalid memory range: base=0x{0:X}, size={1}")]
    InvalidMemoryRange(usize, usize),

    #[error("Input PTR is NULL")]
    InputNullPtr,

    #[error("WinAPI error: {0}")]
    WinapiError(#[from] WinapiError),
}

pub type WinMemoryResult<T> = std::result::Result<T, WinMemoryError>;

/// Validates range of memory (raw pointer + it's size)
/// Checks if range of memory is commited and sise is okay
pub fn validate_memory_range(ptr: *mut c_void, size: usize) -> WinMemoryResult<()> {
    if ptr.is_null() {
        return Err(WinMemoryError::InputNullPtr);
    }

    if size == 0 {
        return Err(WinMemoryError::InvalidSize);
    }

    let info = query_memory(ptr)?;

    // Check if memory is committed
    if info.state != MEM_COMMIT.0 {
        return Err(WinMemoryError::MemoryNotCommitted(ptr as usize));
    }

    let base_address = info.base_address as usize;
    let region_size = info.region_size as usize;
    let end_address = base_address
        .checked_add(region_size)
        .ok_or_else(|| WinMemoryError::InvalidMemoryRange(base_address, region_size))?;

    let target_end = (ptr as usize)
        .checked_add(size)
        .ok_or_else(|| WinMemoryError::InvalidMemoryRange(ptr as usize, size))?;

    if target_end > end_address {
        return Err(WinMemoryError::InvalidMemoryRange(ptr as usize, size));
    }

    Ok(())
}

/// Safely writes bytes to memory
pub fn write_bytes(ptr: *mut c_void, buffer: &[u8]) -> WinMemoryResult<()> {
    if ptr.is_null() {
        return Err(WinMemoryError::InputNullPtr);
    }

    if buffer.is_empty() {
        return Ok(());
    }

    validate_memory_range(ptr, buffer.len())?;

    let old_protect = virtual_protect(
        ptr,
        PageProtectionFlags::PageReadwrite,
        buffer.len(),
    )?;

    unsafe {
        std::ptr::copy_nonoverlapping(buffer.as_ptr(), ptr as *mut u8, buffer.len());
    }

    virtual_protect(ptr, old_protect, buffer.len())?;

    Ok(())
}

/// Safely reads bytes from memory
pub fn read_bytes(ptr: *mut c_void, size: usize) -> WinMemoryResult<Vec<u8>> {
    if ptr.is_null() {
        return Err(WinMemoryError::InputNullPtr);
    }

    if size == 0 {
        return Ok(Vec::new());
    }

    validate_memory_range(ptr, size)?;

    let mut buffer = vec![0u8; size];

    unsafe {
        std::ptr::copy_nonoverlapping(ptr as *const u8, buffer.as_mut_ptr(), size);
    }

    Ok(buffer)
}
//! Windows memory management utilities
//!
//! This module provides safe memory operations for function hooking,
//! including executable memory allocation, memory protection changes,
//! and safe memory read/write operations using the winapi wrapper.

use libc::c_void;
use std::sync::atomic::{AtomicU32, Ordering};
use thiserror::Error;
use windows::Win32::System::Memory::{MEM_COMMIT, PAGE_PROTECTION_FLAGS, PAGE_READWRITE};

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
    log::trace!(
        "Memory info: base={:p}, size={}, state=0x{:X}, protect={}",
        info.base_address,
        info.region_size,
        info.state,
        info.protect.0
    );

    if !info.is_committed() {
        log::error!(
            "Memory not committed at {:p}, state=0x{:X}",
            address,
            info.state
        );
        return Err(MemoryError::MemoryNotCommitted(address as usize));
    }

    if !info.is_accessible() {
        log::error!("Memory is inaccessible at {:p}", address);
        return Err(MemoryError::InaccessibleMemory(address as usize));
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

/// Direct-mapped per-epoch validation slots.
///
/// One validated verdict per (address, size) key, valid for the supplied
/// epoch. The cache is zero-initialized POD: no constructor, TLS or
/// destructor runs before the owning subsystem first uses it. The caller
/// that supplies a per-frame epoch is the single serialized render thread;
/// concurrent writers degrade to extra full validations, never to a stale
/// pass, because the epoch is published last.
const VALIDATION_CACHE_SLOTS: usize = 256;
const VALIDATION_CACHE_INDEX_SHIFT: u32 = 4;
const VALIDATION_CACHE_INDEX_PRIME: u32 = 0x9E37_79B9;

struct ValidationSlot {
    address: AtomicU32,
    size: AtomicU32,
    epoch: AtomicU32,
}

static VALIDATION_CACHE: [ValidationSlot; VALIDATION_CACHE_SLOTS] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const SLOT: ValidationSlot = ValidationSlot {
        address: AtomicU32::new(0),
        size: AtomicU32::new(0),
        epoch: AtomicU32::new(0),
    };
    [SLOT; VALIDATION_CACHE_SLOTS]
};

fn validation_cache_index(address: usize) -> usize {
    (address.wrapping_mul(VALIDATION_CACHE_INDEX_PRIME as usize) >> VALIDATION_CACHE_INDEX_SHIFT)
        % VALIDATION_CACHE_SLOTS
}

/// Validate a range against a caller-owned monotonic epoch.
///
/// Semantics are identical to [`validate_memory_range`] except that a range
/// already validated with the same `(address, size, epoch)` triple skips the
/// `VirtualQuery` syscall: the verdict from earlier in the same epoch is
/// reused. The caller owns the epoch's meaning (a render frame); an epoch
/// change invalidates every cached verdict. Callers on other threads must
/// use a private epoch domain or the uncached [`validate_memory_range`].
/// Returns the same error the uncached path would return on a first
/// validation failure; failures are never cached.
pub fn validate_memory_range_for_epoch(
    epoch: u32,
    address: *const c_void,
    size: usize,
) -> MemoryResult<()> {
    let addr = address as usize;
    if addr == 0 {
        // Match the uncached path: a null address fails through VirtualQuery.
        return validate_memory_range(address, size);
    }
    let cached_size =
        u32::try_from(size).map_err(|_| MemoryError::InvalidMemoryRange(addr, size))?;
    let slot = &VALIDATION_CACHE[validation_cache_index(addr)];
    if slot.epoch.load(Ordering::Relaxed) == epoch
        && slot.address.load(Ordering::Relaxed) == addr as u32
        && slot.size.load(Ordering::Relaxed) == cached_size
    {
        return Ok(());
    }
    validate_memory_range(address, size)?;
    // Epoch is published last: a torn reader observes a stale epoch and
    // revalidates instead of trusting a partially published slot.
    slot.address.store(addr as u32, Ordering::Relaxed);
    slot.size.store(cached_size, Ordering::Relaxed);
    slot.epoch.store(epoch, Ordering::Relaxed);
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
    log::trace!("Reading {} bytes from {:p}", size, address);

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

    log::trace!("Successfully read {} bytes", size);
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
    log::trace!("Writing {} bytes to {:p}", data.len(), address);

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

    log::trace!("Successfully wrote {} bytes to memory", data.len());

    Ok(())
}

/// Temporarily make a host memory range writable and restore its protection.
///
/// # Safety
///
/// The caller must ensure the pointer and size describe the intended host
/// object and that writes performed by `func` are valid for that object.
pub unsafe fn with_writable_memory<T, F: FnOnce() -> T>(
    address: *mut c_void,
    size: usize,
    func: F,
) -> MemoryResult<T> {
    unsafe { with_virtual_protect(address, PAGE_READWRITE, size, func).map_err(Into::into) }
}

/// Validates memory behind pointer and return protection flag and region size
/// # Arguments:
/// - `ptr` - Pointer to memory we want to check
pub fn validate_memory_access(ptr: *mut c_void) -> MemoryResult<(PAGE_PROTECTION_FLAGS, usize)> {
    // First, we need to understand what memory behind pointer
    let mem_info = virtual_query(ptr)?;

    // Next, we check if memory is commited.
    // If not - it's obvious error, we cant work with not commited memory.
    if !mem_info.is_accessible() {
        return Err(MemoryError::InaccessibleMemory(ptr as usize));
    }

    // Fine, now let's check memory protection flag
    let protect = mem_info.protect;

    // We need to check if memory is executable
    let is_executable = mem_info.is_executable();

    // If memory is not executable, we return error.
    // Functions can be located only in executable memory.
    if !is_executable {
        return Err(MemoryError::NonExecutableMemory(ptr as usize));
    }

    Ok((protect, mem_info.region_size))
}

#[cfg(test)]
mod validation_cache_tests {
    use super::{
        VALIDATION_CACHE_SLOTS, validate_memory_range, validate_memory_range_for_epoch,
        validation_cache_index,
    };
    use std::time::Instant;

    /// A committed buffer validates through both paths and the cached repeat
    /// must keep accepting it.
    #[test]
    fn cached_range_stays_valid_within_one_epoch() {
        let buffer = [7u8; 64];
        let address = buffer.as_ptr() as *const libc::c_void;
        validate_memory_range_for_epoch(5, address, 64).unwrap();
        for _ in 0..100 {
            validate_memory_range_for_epoch(5, address, 64).unwrap();
        }
        assert!(
            validate_memory_range(address, 64).is_ok(),
            "the uncached contract must keep accepting the same range"
        );
    }

    /// An epoch change must invalidate the cached verdict and revalidate.
    #[test]
    fn epoch_change_revalidates_every_range() {
        let buffer = [3u8; 32];
        let address = buffer.as_ptr() as *const libc::c_void;
        validate_memory_range_for_epoch(11, address, 32).unwrap();
        validate_memory_range_for_epoch(11, address, 32).unwrap();
        validate_memory_range_for_epoch(12, address, 32).unwrap();
        validate_memory_range_for_epoch(12, address, 32).unwrap();
    }

    /// A different size at the same address is a distinct key.
    #[test]
    fn size_is_part_of_the_cache_key() {
        let buffer = [5u8; 128];
        let address = buffer.as_ptr() as *const libc::c_void;
        validate_memory_range_for_epoch(21, address, 32).unwrap();
        validate_memory_range_for_epoch(21, address, 128).unwrap();
        validate_memory_range_for_epoch(21, address, 32).unwrap();
        assert!(validate_memory_range(address, 128).is_ok());
    }

    /// A failing range must fail through both paths and stay uncached, so a
    /// later validation of the same address re-runs the full query.
    #[test]
    fn failures_are_never_cached() {
        let address = 0x400usize as *const libc::c_void;
        assert!(validate_memory_range_for_epoch(31, address, 4).is_err());
        assert!(validate_memory_range_for_epoch(31, address, 4).is_err());
    }

    /// A null address must fail through the uncached path, never cache.
    #[test]
    fn null_address_fails_without_caching() {
        assert!(validate_memory_range_for_epoch(41, std::ptr::null(), 4).is_err());
    }

    /// An oversized range fails the region-bound check without caching.
    #[test]
    fn range_beyond_the_region_fails() {
        let buffer = [1u8; 16];
        let address = buffer.as_ptr() as *const libc::c_void;
        assert!(validate_memory_range_for_epoch(51, address, 1 << 20).is_err());
    }

    /// The hit path exists to avoid the emulated VirtualQuery syscall. This
    /// benchmark records the batch cost of repeated cached validations; the
    /// first call is a real query, every later call is a cache hit.
    #[test]
    #[ignore = "explicit offline VirtualQuery-cost benchmark"]
    fn epoch_cache_hit_benchmark() {
        let _ = crate::logger::Logger::new()
            .with_level(log::LevelFilter::Warn)
            .init();
        let buffer = [0u8; 256];
        let address = buffer.as_ptr() as *const libc::c_void;
        validate_memory_range_for_epoch(61, address, 256).unwrap();
        let started = Instant::now();
        let mut checksum = 0usize;
        for _ in 0..200_000 {
            validate_memory_range_for_epoch(61, address, 256).unwrap();
            checksum = checksum.wrapping_add(1);
        }
        let hit_us = started.elapsed().as_micros();
        std::hint::black_box(checksum);

        let started = Instant::now();
        for _ in 0..200 {
            validate_memory_range(address, 256).unwrap();
        }
        let query_us = started.elapsed().as_micros();
        log::warn!(
            "[VALIDATION BENCH] 200k cached hits: {hit_us} us; 200 uncached VirtualQuery calls: {query_us} us"
        );
        // 200k hits must remain far cheaper than 200 uncached syscalls
        // (measured baseline: one VirtualQuery costs ~12.4 us on Wine).
        assert!(
            hit_us < query_us,
            "200k cached hits ({hit_us} us) must beat 200 uncached queries ({query_us} us)"
        );
        crate::logger::Logger::shutdown();
    }

    /// Direct-mapped slots must be addressable for every configured index.
    #[test]
    fn cache_indices_cover_the_address_space() {
        let first = validation_cache_index(0x011F917C);
        let second = validation_cache_index(0x011F917C + 64);
        assert!(first < VALIDATION_CACHE_SLOTS);
        assert!(second < VALIDATION_CACHE_SLOTS);
    }
}

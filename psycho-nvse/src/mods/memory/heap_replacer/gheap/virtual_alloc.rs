//! Large allocation pool with pre-reserved VAS.
//!
//! Inspired by NVHR's pool reservation strategy: at startup, we reserve a
//! contiguous region of virtual address space (256MB). Large allocations
//! (>= 64KB) commit pages within this region instead of getting their own
//! VirtualAlloc regions. When freed, pages are decommitted (MEM_DECOMMIT)
//! but the reservation stays, preventing VAS fragmentation.
//!
//! Header layout for pool allocations:
//!   +0x00  magic1: u32  = 0x5641504C ("VAPL")
//!   +0x04  magic2: u32  = 0xA9BEAFB3 (~magic1)
//!   +0x08  alloc_size: usize
//!   +0x0C  in_pool: u8  (1 = pool, 0 = individual)
//!   +0x0D  [padding to 16-byte alignment]
//!   +0x10  USER DATA (16-byte aligned)
//!
//! Header layout for individual VirtualAlloc allocations:
//!   +0x00  magic1: u32  = 0x56414C4C ("VALL")
//!   +0x04  magic2: u32  = 0xA9BEBBB4 (~magic1)
//!   +0x08  alloc_size: usize
//!   +0x0C  in_pool: u8  (0 = individual)
//!   +0x0D  [padding]
//!   +0x10  USER DATA
//!
//! The in_pool flag distinguishes MEM_DECOMMIT (pool) from MEM_RELEASE (individual).

use libc::c_void;
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_DECOMMIT, MEM_RELEASE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_READWRITE,
    VirtualAlloc, VirtualFree, VirtualQuery,
};

const VALL_MAGIC1: u32 = 0x56414C4C; // "VALL" (individual VirtualAlloc)
const VALL_MAGIC2: u32 = 0xA9BEBBB4;
const VAPL_MAGIC1: u32 = 0x5641504C; // "VAPL" (pool allocation)
const VAPL_MAGIC2: u32 = 0xA9BEAFB3;

/// Minimum allocation size to use the large allocation pool.
pub const LARGE_ALLOC_THRESHOLD: usize = 64 * 1024; // 64KB

/// Size of the pre-reserved large allocation pool.
/// Calculated dynamically at startup based on available VAS:
///   < 500MB remaining  → 64MB  (tight VAS, 32-bit LAA)
///   500-1500MB         → 128MB (moderate VAS)
///   > 1500MB           → 256MB (ample VAS, 4GB-patched)
fn calculate_pool_size(available_vas: usize) -> usize {
    let mimalloc_reserved = 512 * 1024 * 1024; // mimalloc arena size
    let remaining = available_vas.saturating_sub(mimalloc_reserved);

    if remaining < 500 * 1024 * 1024 {
        64 * 1024 * 1024  // 64MB - tight VAS
    } else if remaining < 1500 * 1024 * 1024 {
        128 * 1024 * 1024 // 128MB - moderate VAS
    } else {
        256 * 1024 * 1024 // 256MB - ample VAS (4GB-patched)
    }
}

/// Header size added before user data. 16 bytes for alignment.
const HEADER_SIZE: usize = 16;

#[repr(C)]
struct VaHeader {
    magic1: u32,
    magic2: u32,
    alloc_size: usize,
    in_pool: u8, // 1 = pool allocation, 0 = individual VirtualAlloc
}

/// Large allocation pool state. Thread-safe via atomic operations.
struct LargePool {
    /// Base address of the reserved region.
    base: AtomicPtr<c_void>,
    /// Current commit position within the pool.
    current: AtomicUsize,
    /// End of the reserved region.
    end: AtomicUsize,
}

static LARGE_POOL: LargePool = LargePool {
    base: AtomicPtr::new(ptr::null_mut()),
    current: AtomicUsize::new(0),
    end: AtomicUsize::new(0),
};

/// Initialize the large allocation pool by reserving VAS.
/// Called once at startup (after all DLLs loaded, before game starts).
/// `available_vas` is the total available VAS measured by VirtualQuery.
/// Returns the amount of VAS reserved for the large pool.
pub fn init_large_pool(available_vas: usize) -> usize {
    let pool_size = calculate_pool_size(available_vas);

    // Reserve contiguous region
    let base = unsafe {
        VirtualAlloc(
            None,
            pool_size,
            MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if base.is_null() {
        // Failed to reserve — fall back to individual VirtualAlloc for everything
        LARGE_POOL.base.store(ptr::null_mut(), Ordering::Release);
        LARGE_POOL.current.store(0, Ordering::Release);
        LARGE_POOL.end.store(0, Ordering::Release);
        log::warn!(
            "[VIRT] Failed to reserve {}MB large pool. Falling back to individual VirtualAlloc.",
            pool_size / 1024 / 1024,
        );
        return 0;
    }

    let base_usize = base as usize;
    LARGE_POOL.base.store(base, Ordering::Release);
    LARGE_POOL.current.store(base_usize, Ordering::Release);
    LARGE_POOL.end.store(base_usize + pool_size, Ordering::Release);

    log::info!(
        "[VIRT] Large pool reserved: 0x{:08X}-0x{:08X} ({}MB), available VAS={}MB",
        base_usize,
        base_usize + pool_size,
        pool_size / 1024 / 1024,
        available_vas / 1024 / 1024,
    );

    pool_size
}

/// Allocate `size` bytes. Uses the large pool if available, falls back to
/// individual VirtualAlloc if pool is exhausted.
///
/// Returns a 16-byte-aligned user pointer. The header is 16 bytes before
/// the returned pointer.
pub unsafe fn malloc(size: usize) -> *mut c_void {
    // Try to allocate from the large pool
    let pool_base = LARGE_POOL.base.load(Ordering::Acquire);
    if !pool_base.is_null() {
        loop {
            let current = LARGE_POOL.current.load(Ordering::Acquire);
            let total = size + HEADER_SIZE;
            let new_current = current + total;

            // Check if we have enough space in the pool
            if new_current > LARGE_POOL.end.load(Ordering::Acquire) {
                // Pool exhausted — fall through to individual VirtualAlloc
                break;
            }

            // Try to claim this space atomically
            if LARGE_POOL
                .current
                .compare_exchange_weak(current, new_current, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                // Successfully claimed space — commit pages
                let alloc_base = current as *mut c_void;
                let committed = unsafe {
                    VirtualAlloc(
                        Some(alloc_base),
                        total,
                        MEM_COMMIT,
                        PAGE_READWRITE,
                    )
                };

                if committed.is_null() {
                    // Commit failed (shouldn't happen with MEM_RESERVE)
                    // Reset current pointer and try individual VirtualAlloc
                    LARGE_POOL.current.store(current, Ordering::Release);
                    break;
                }

                // Write header
                let header = committed as *mut VaHeader;
                ptr::write(
                    header,
                    VaHeader {
                        magic1: VAPL_MAGIC1,
                        magic2: VAPL_MAGIC2,
                        alloc_size: size,
                        in_pool: 1,
                    },
                );

                // Return user pointer (base + 16, 16-byte aligned)
                return (committed as usize + HEADER_SIZE) as *mut c_void;
            }
            // CAS failed — another thread claimed this space, retry
        }
    }

    // Fallback: individual VirtualAlloc
    let total = size + HEADER_SIZE;
    let base = unsafe {
        VirtualAlloc(
            None,
            total,
            MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    if base.is_null() {
        return ptr::null_mut();
    }

    // Write header
    let header = base as *mut VaHeader;
    ptr::write(
        header,
        VaHeader {
            magic1: VALL_MAGIC1,
            magic2: VALL_MAGIC2,
            alloc_size: size,
            in_pool: 0,
        },
    );

    // Return user pointer (base + 16, 16-byte aligned)
    (base as usize + HEADER_SIZE) as *mut c_void
}

/// Free a large allocation.
///
/// Returns `true` if the pointer was a valid large allocation and was freed.
/// Returns `false` if the pointer is not a large allocation (caller should
/// try other free paths).
///
/// Pool allocations: MEM_DECOMMIT (pages returned to OS, reservation stays)
/// Individual allocations: MEM_RELEASE (entire region released)
pub unsafe fn free(ptr: *mut c_void) -> bool {
    if ptr.is_null() {
        return false;
    }

    let header_addr = (ptr as *const u8).wrapping_sub(HEADER_SIZE) as *const c_void;

    // VirtualQuery to verify the region is valid
    let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
    let query_result = unsafe {
        VirtualQuery(
            Some(header_addr),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if query_result == 0 {
        return false; // Unmapped or invalid address
    }
    if mbi.State != MEM_COMMIT {
        return false; // Not a committed region
    }

    // Safe to read header
    let header = header_addr as *const VaHeader;
    let magic1 = unsafe { ptr::read_volatile(&(*header).magic1) };
    let magic2 = unsafe { ptr::read_volatile(&(*header).magic2) };
    let in_pool = unsafe { (*header).in_pool };

    if (magic1 == VAPL_MAGIC1 && magic2 == VAPL_MAGIC2) && in_pool == 1 {
        // Pool allocation: decommit pages but keep reservation
        let alloc_size = unsafe { (*header).alloc_size };
        let total = alloc_size + HEADER_SIZE;
        let _ = unsafe { VirtualFree(header_addr as *mut c_void, total, MEM_DECOMMIT) };
        true
    } else if magic1 == VALL_MAGIC1 && magic2 == VALL_MAGIC2 {
        // Individual VirtualAlloc allocation: release entire region
        let _ = unsafe { VirtualFree(header_addr as *mut c_void, 0, MEM_RELEASE) };
        true
    } else {
        false // Not our header
    }
}

/// Return the allocation size for a large allocation pointer.
///
/// Returns `Some(size)` if the pointer is a valid large allocation,
/// `None` otherwise.
pub unsafe fn msize(ptr: *mut c_void) -> Option<usize> {
    if ptr.is_null() {
        return None;
    }

    let header_addr = (ptr as *const u8).wrapping_sub(HEADER_SIZE) as *const c_void;
    let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
    let query_result = unsafe {
        VirtualQuery(
            Some(header_addr),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if query_result == 0 || mbi.State != MEM_COMMIT {
        return None;
    }

    let header = header_addr as *const VaHeader;
    let magic1 = unsafe { ptr::read_volatile(&(*header).magic1) };
    let magic2 = unsafe { ptr::read_volatile(&(*header).magic2) };

    if (magic1 == VAPL_MAGIC1 && magic2 == VAPL_MAGIC2)
        || (magic1 == VALL_MAGIC1 && magic2 == VALL_MAGIC2)
    {
        Some(unsafe { (*header).alloc_size })
    } else {
        None
    }
}

/// Reallocate a large allocation to a new size.
///
/// If `old_ptr` is a large allocation, creates a new one, copies data,
/// frees the old one. If not, returns `None`.
pub unsafe fn realloc(old_ptr: *mut c_void, new_size: usize) -> Option<*mut c_void> {
    if old_ptr.is_null() {
        return Some(unsafe { malloc(new_size) });
    }

    let old_size = match unsafe { msize(old_ptr) } {
        Some(s) => s,
        None => return None, // Not our allocation
    };

    if new_size == 0 {
        unsafe { free(old_ptr) };
        return Some(ptr::null_mut());
    }

    let new_ptr = unsafe { malloc(new_size) };
    if new_ptr.is_null() {
        return None;
    }

    let copy_size = old_size.min(new_size);
    unsafe {
        ptr::copy_nonoverlapping(
            old_ptr as *const u8,
            new_ptr as *mut u8,
            copy_size,
        );
    }
    unsafe { free(old_ptr) };

    Some(new_ptr)
}

/// Get pool usage statistics.
/// Returns (reserved_mb, committed_mb, remaining_mb).
pub fn pool_stats() -> (usize, usize, usize) {
    let base = LARGE_POOL.base.load(Ordering::Acquire) as usize;
    let current = LARGE_POOL.current.load(Ordering::Acquire);
    let end = LARGE_POOL.end.load(Ordering::Acquire);

    if base == 0 || end == 0 {
        return (0, 0, 0);
    }

    let reserved = end - base;
    let committed = current - base;
    let remaining = end - current;

    (reserved / 1024 / 1024, committed / 1024 / 1024, remaining / 1024 / 1024)
}

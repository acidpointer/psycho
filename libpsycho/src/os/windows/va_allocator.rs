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
    MEM_COMMIT, MEM_DECOMMIT, MEM_RELEASE, MEMORY_BASIC_INFORMATION, PAGE_READWRITE,
    VirtualAlloc, VirtualFree, VirtualQuery,
};

/// Magic numbers for VirtualAlloc allocation headers.
pub const VALL_MAGIC1: u32 = 0x56414C4C; // "VALL" (individual VirtualAlloc)
pub const VALL_MAGIC2: u32 = 0xA9BEBBB4;
pub const VAPL_MAGIC1: u32 = 0x5641504C; // "VAPL" (pool allocation)
pub const VAPL_MAGIC2: u32 = 0xA9BEAFB3;

/// Check if a pointer is a VirtualAlloc allocation by reading the header magic.
/// NO sys call — just reads memory at `ptr - 16`.
/// Returns true if the pointer has our VirtualAlloc header magic.
///
/// Safety: Caller must ensure `ptr - 16` is readable memory. This is guaranteed
/// for any pointer returned by our VirtualAlloc allocator. For unknown pointers,
/// this function may read garbage (but won't crash if the page is committed).
#[inline]
pub unsafe fn is_virtual_alloc_ptr(ptr: *mut c_void) -> bool {
    if ptr.is_null() {
        return false;
    }
    // Check minimum pointer value to avoid reading NULL guard page.
    // Windows reserves the first 64KB (0x00000000-0x0000FFFF) as a guard page.
    // Reading from this region causes an access violation. Our VirtualAlloc
    // allocations start at 0x10000 minimum, so any pointer below this is
    // definitely not ours.
    let addr = ptr as usize;
    if addr < 0x10000 {
        return false;
    }

    let header = (addr - HEADER_SIZE) as *const VaHeader;
    let magic1 = unsafe { ptr::read_volatile(&(*header).magic1) };
    let magic2 = unsafe { ptr::read_volatile(&(*header).magic2) };

    (magic1 == VAPL_MAGIC1 && magic2 == VAPL_MAGIC2)
        || (magic1 == VALL_MAGIC1 && magic2 == VALL_MAGIC2)
}

/// Minimum allocation size to use the large allocation pool.
/// 1MB chosen so that:
/// - Havok shapes (100KB-500KB) --> mimalloc (UAF protected)
/// - NiRefObjects (16-1200B) --> mimalloc (UAF protected)
/// - Terrain meshes, DDS files (1MB+) --> VirtualAlloc (VAS reclaimed)
///   Game objects rarely exceed 1MB. Raw data buffers often do.
pub const LARGE_ALLOC_THRESHOLD: usize = 1024 * 1024; // 1MB

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
                unsafe { ptr::write(
                    header,
                    VaHeader {
                        magic1: VAPL_MAGIC1,
                        magic2: VAPL_MAGIC2,
                        alloc_size: size,
                        in_pool: 1,
                    },
                ) };

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
    unsafe { ptr::write(
        header,
        VaHeader {
            magic1: VALL_MAGIC1,
            magic2: VALL_MAGIC2,
            alloc_size: size,
            in_pool: 0,
        },
    ) };

    // Return user pointer (base + 16, 16-byte aligned)
    (base as usize + HEADER_SIZE) as *mut c_void
}

/// Free a VirtualAlloc allocation.
///
/// Caller MUST have already verified the header magic via `is_virtual_alloc_ptr()`.
/// This function does NOT perform VirtualQuery — it directly frees the allocation.
///
/// Pool allocations: MEM_DECOMMIT (pages returned to OS, reservation stays)
/// Individual allocations: MEM_RELEASE (entire region released)
pub unsafe fn free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }

    let header_addr = (ptr as *const u8).wrapping_sub(HEADER_SIZE) as *const VaHeader;
    let in_pool = unsafe { (*header_addr).in_pool };

    if in_pool == 1 {
        // Pool allocation: decommit pages but keep reservation
        let alloc_size = unsafe { (*header_addr).alloc_size };
        let total = alloc_size + HEADER_SIZE;
        let _ = unsafe { VirtualFree(header_addr as *mut c_void, total, MEM_DECOMMIT) };
    } else {
        // Individual VirtualAlloc allocation: release entire region
        let _ = unsafe { VirtualFree(header_addr as *mut c_void, 0, MEM_RELEASE) };
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
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
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

    let old_size = unsafe { msize(old_ptr) }?;

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

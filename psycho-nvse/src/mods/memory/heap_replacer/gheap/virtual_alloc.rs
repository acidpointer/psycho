//! VirtualAlloc-based allocator for large CRT allocations (>= 64KB).
//!
//! Large raw buffer allocations (textures, geometry, audio) are routed
//! through VirtualAlloc instead of mimalloc. This prevents them from
//! consuming mimalloc arena pages that can't be efficiently reclaimed
//! during VAS crises.
//!
//! Each allocation has a 16-byte header:
//!   +0x00  magic1: u32  = 0x56414C4C ("VALL")
//!   +0x04  magic2: u32  = 0xA9BEBBB4 (~magic1)
//!   +0x08  alloc_size: usize
//!   +0x0C  [padding]
//!   +0x10  USER DATA (returned to caller, 16-byte aligned)
//!
//! The user pointer is base + 16. At free time, we read the header at
//! ptr - 16 after verifying the region is MEM_PRIVATE via VirtualQuery.

use libc::c_void;
use std::ptr;

use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_PRIVATE, MEM_RELEASE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
    VirtualQuery, MEMORY_BASIC_INFORMATION,
};

const VALL_MAGIC1: u32 = 0x56414C4C; // "VALL"
const VALL_MAGIC2: u32 = 0xA9BEBBB4; // ~magic1

/// Minimum allocation size to use VirtualAlloc.
/// Below this, mimalloc is more efficient.
pub const LARGE_ALLOC_THRESHOLD: usize = 64 * 1024; // 64KB

/// Header size added before user data. 16 bytes for alignment.
const HEADER_SIZE: usize = 16;

/// Allocate `size` bytes via VirtualAlloc with header.
///
/// Returns a 16-byte-aligned user pointer. The actual VirtualAlloc base
/// is 16 bytes before the returned pointer (holds the header).
///
/// # Safety
/// `size` must be > 0. Caller must ensure this.
pub unsafe fn malloc(size: usize) -> *mut c_void {
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

    // Write header at base
    let header = base as *mut VaHeader;
    unsafe { ptr::write(header, VaHeader {
        magic1: VALL_MAGIC1,
        magic2: VALL_MAGIC2,
        alloc_size: size,
    }) };

    // Return user pointer (base + 16, 16-byte aligned since base is 4KB-aligned)
    (base as usize + HEADER_SIZE) as *mut c_void
}

/// Free a VirtualAlloc allocation.
///
/// Returns `true` if the pointer was a valid VirtualAlloc allocation and
/// was freed. Returns `false` if the pointer is not a VirtualAlloc
/// allocation (caller should try other free paths).
///
/// Uses VirtualQuery to verify the region type before reading the header,
/// preventing crashes on garbage pointers.
pub unsafe fn free(ptr: *mut c_void) -> bool {
    if ptr.is_null() {
        return false;
    }

    let header_addr = (ptr as *const u8).wrapping_sub(HEADER_SIZE) as *const c_void;

    // VirtualQuery to verify the region is MEM_PRIVATE (VirtualAlloc creates this)
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
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
    if mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE {
        return false; // Not a VirtualAlloc region
    }

    // Safe to read header
    let header = header_addr as *const VaHeader;
    let magic1 = unsafe { ptr::read_volatile(&(*header).magic1) };
    let magic2 = unsafe { ptr::read_volatile(&(*header).magic2) };

    if magic1 != VALL_MAGIC1 || magic2 != VALL_MAGIC2 {
        return false; // Not our header
    }

    // Free the base address (header + user data)
    let base_ptr = header_addr as *mut c_void;
    let _ = unsafe { VirtualFree(base_ptr, 0, MEM_RELEASE) };
    true
}

/// Return the allocation size for a VirtualAlloc pointer.
///
/// Returns `Some(size)` if the pointer is a valid VirtualAlloc allocation,
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
    if query_result == 0 || mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE {
        return None;
    }

    let header = header_addr as *const VaHeader;
    let magic1 = unsafe { ptr::read_volatile(&(*header).magic1) };
    let magic2 = unsafe { ptr::read_volatile(&(*header).magic2) };

    if magic1 == VALL_MAGIC1 && magic2 == VALL_MAGIC2 {
        Some(unsafe { (*header).alloc_size })
    } else {
        None
    }
}

/// Reallocate a VirtualAlloc allocation to a new size.
///
/// If `old_ptr` is a VirtualAlloc allocation, creates a new VirtualAlloc
/// region, copies data, frees the old one.
///
/// If `old_ptr` is NOT a VirtualAlloc allocation, returns `None` (caller
/// should use mimalloc realloc instead).
///
/// Returns `Some(new_ptr)` on success, `None` on allocation failure
/// or if old_ptr is not a VirtualAlloc allocation.
pub unsafe fn realloc(old_ptr: *mut c_void, new_size: usize) -> Option<*mut c_void> {
    if old_ptr.is_null() {
        // NULL realloc → malloc
        return Some(unsafe { malloc(new_size) });
    }

    // Verify old_ptr is a VirtualAlloc allocation
    let old_size = unsafe { msize(old_ptr) }?;

    if new_size == 0 {
        // realloc to 0 → free
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

#[repr(C)]
struct VaHeader {
    magic1: u32,
    magic2: u32,
    alloc_size: usize,
}

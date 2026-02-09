use libc::c_void;
use libmimalloc::*;
use log::{debug, info, trace, warn};
use scc::HashMap;
use parking_lot::Mutex;
use windows::Win32::System::Memory::PAGE_READWRITE;
use std::ptr::{self, copy_nonoverlapping, null_mut};
use std::sync::LazyLock;

use libpsycho::os::windows::winapi::{
    AllocationType, FreeType, virtual_alloc, virtual_free,
};

// ============================================================================
// Constants
// ============================================================================

const MAGIC: u32 = 0xDEAD_C0DE;
const CHECK_SALT: u16 = 0xCAFE;

const HEADER_SIZE: usize = size_of::<BlockHeader>();
const PAYLOAD_ALIGN: usize = 16;
const HEADER_ALIGN: usize = std::mem::align_of::<BlockHeader>();
const RAW_ALIGN: usize = if PAYLOAD_ALIGN > HEADER_ALIGN { PAYLOAD_ALIGN } else { HEADER_ALIGN };


// Threshold for large allocations that should bypass mimalloc
const LARGE_ALLOC_THRESHOLD: usize = 1 * 1024 * 1024; // 1 MB

// Flags for BlockHeader
const FLAG_LARGE: u16 = 0x1;

// On 32-bit systems: header is 16 bytes (magic:4 + flags:2 + check:2 + handle:4 + payload_size:4)
// On 64-bit systems: header is 20 bytes (magic:4 + flags:2 + check:2 + handle:8 + payload_size:4)
// Since this is for 32-bit Fallout NV, the header will be 16 bytes on 32-bit
// Conditional assertions based on target architecture
#[cfg(target_pointer_width = "32")]
const _: () = assert!(std::mem::size_of::<BlockHeader>() == 16);
#[cfg(target_pointer_width = "64")]
compile_error!("This allocator is 32-bit only (Fallout NV)");

// ============================================================================
// Large allocation functions
// ============================================================================

unsafe fn large_alloc(size: usize) -> *mut c_void {
    // Two-step allocation: reserve first, then commit
    // This matches the original engine behavior and handles fragmented VA space
    let reserved_ptr = match unsafe { virtual_alloc(
        None, // Let system choose address
        size,
        AllocationType::Reserve,
        PAGE_READWRITE,
    ) } {
        Ok(ptr) => ptr,
        Err(_) => return null_mut(), // Reservation failed
    };

    if reserved_ptr.is_null() {
        return null_mut();
    }

    // Now commit the reserved region
    match unsafe { virtual_alloc(
        Some(reserved_ptr),
        size,
        AllocationType::Commit,
        PAGE_READWRITE,
    ) } {
        Ok(ptr) => ptr,
        Err(_) => {
            // If commit fails, release the reservation to avoid leaks
            let _ = unsafe { virtual_free(reserved_ptr, FreeType::Release) };
            null_mut() // Return null on commit failure
        }
    }
}

unsafe fn large_free(ptr: *mut c_void) {
    let _ = unsafe { virtual_free(ptr, FreeType::Release) }; // Ignore error on free
}

// ============================================================================
// Block Header — 16 bytes, prepended to every allocation
// ============================================================================

/// `[BlockHeader 20B on 32-bit | payload aligned]`
///
/// The payload starts at `raw + HEADER_SIZE` and is what the game engine sees.
/// All header fields are preserved while the block is alive.
///
/// Validation: primary magic (32-bit) + integrity check (16-bit) = 48 bits.
/// False positive rate per foreign pointer: ~1 in 2^48.
#[repr(C)]
struct BlockHeader {
    magic: u32,
    flags: u16, // FLAG_LARGE | FLAG_BUCKETED
    check: u16,
    handle: usize, // Store the original handle used to allocate this block
    payload_size: u32, // Size of the payload (actual requested size)
}


/// Metadata extracted from a header before invalidation.
struct BlockMeta {
    raw: *mut c_void,
    handle: usize,
    is_large: bool,
    payload_size: u32,
}

#[inline(always)]
fn make_check_from_parts(handle_val: usize, flags: u16) -> u16 {
    // Mix handle with raw address for better entropy, and include flags
    let mixed = handle_val.rotate_left(13) ^ flags as usize;
    ((mixed >> 4) as u16) ^ ((mixed >> 16) as u16) ^ ((mixed >> 20) as u16) ^ flags ^ CHECK_SALT
}

// We no longer store bucket index in the header directly
// Instead, we determine if it was bucketed based on size and allocation path

impl BlockHeader {
    /// Validate a game payload pointer and recover the header.
    /// Returns `None` for foreign pointers — expected when the engine frees
    /// CRT or vanilla-heap allocations through our hooks during save load.
    #[inline]
    unsafe fn from_payload(payload: *mut c_void) -> Option<*mut Self> {
        let addr = payload as usize;
        if addr < HEADER_SIZE || !addr.is_multiple_of(PAYLOAD_ALIGN) {
            return None;
        }

        let header = (addr - HEADER_SIZE) as *mut Self;
        let h = unsafe { &*header };

        if h.magic != MAGIC {
            return None;
        }
        if h.check != make_check_from_parts(h.handle, h.flags) {
            warn!("corrupted header at {payload:?}: magic OK, check mismatch");
            return None;
        }

        Some(header)
    }

    #[inline(always)]
    unsafe fn to_payload(raw: *mut c_void) -> *mut c_void {
        unsafe { (raw as *mut u8).add(HEADER_SIZE) as *mut c_void }
    }

    /// Write a fresh header at `raw`, return the payload pointer.
    unsafe fn write(raw: *mut c_void, handle: *mut c_void, is_large: bool, payload_size: usize) -> *mut c_void {
        unsafe {
            let flags = if is_large { FLAG_LARGE } else { 0 };
            let handle_val = handle as usize;
            ptr::write(
                raw as *mut Self,
                BlockHeader {
                    magic: MAGIC,
                    flags,
                    check: make_check_from_parts(handle_val, flags), // Use handle instead of heap for checksum
                    handle: handle_val,
                    payload_size: payload_size as u32, // Store the payload size
                },
            );
            Self::to_payload(raw)
        }
    }

    /// Invalidate the header and extract metadata. Must not be read after this.
    unsafe fn take(header: *mut Self) -> BlockMeta {
        let h = unsafe { &mut *header };
        let meta = BlockMeta {
            raw: header as *mut c_void,
            handle: h.handle,
            is_large: (h.flags & FLAG_LARGE) != 0,
            payload_size: h.payload_size,
        };
        h.magic = 0;
        meta
    }

    /// Read metadata without invalidating (realloc in-place check).
    unsafe fn peek(header: *mut Self) -> BlockMeta {
        let h = unsafe { &*header };
        BlockMeta {
            raw: header as *mut c_void,
            handle: h.handle,
            is_large: (h.flags & FLAG_LARGE) != 0,
            payload_size: h.payload_size,
        }
    }
}

// ============================================================================
// Bucket math
// ============================================================================


/// Payload capacity for a given block. For large allocations, we use the stored payload size.
/// For small allocations, we use mi_usable_size to get the actual capacity, with stored size as minimum.
#[inline]
fn block_capacity(raw: *mut c_void, is_large: bool, stored_payload_size: u32) -> usize {
    if is_large {
        // For large allocations, use the stored payload size from the header
        stored_payload_size as usize
    } else {
        // For small allocations, use mi_usable_size to get actual capacity,
        // but ensure it's at least the stored payload size to prevent underflow
        let usable = unsafe { mi_usable_size(raw) };
        let cap = usable.saturating_sub(HEADER_SIZE);
        cap.max(stored_payload_size as usize)
    }
}

// GHeap — per-handle allocator backed by mimalloc
// ============================================================================

pub struct GHeap {
    // Empty struct - just serves as identifier for registry
    // All allocations use the global mimalloc heap to ensure thread safety
}

unsafe impl Send for GHeap {}
unsafe impl Sync for GHeap {}

impl GHeap {
    fn new() -> Self {
        Self {}
    }

    fn raw_alloc_with_fallback(&self, total: usize) -> (*mut c_void, bool) {
        // Use large allocation for objects >= 1MB, and avoid bucketing for anything above ~64KB
        let mut is_large = total >= LARGE_ALLOC_THRESHOLD;
        let mut raw = if is_large {
            unsafe { large_alloc(total) }
        } else {
            // For small allocations, use mimalloc
            unsafe { mi_malloc_aligned(total, RAW_ALIGN) }
        };

        if raw.is_null() {
            warn!("raw_alloc: primary backing returned null for {total} bytes, attempting fallback");
            // Fallback: try opposite allocation method
            if is_large {
                // Already tried large alloc, try mimalloc as fallback
                raw = unsafe { mi_malloc_aligned(total, RAW_ALIGN) };
                is_large = false; // Update flag to reflect actual allocation path
            } else {
                // Try large allocation as fallback
                raw = unsafe { large_alloc(total) };
                is_large = true; // Update flag to reflect actual allocation path
            }
        }

        (raw, is_large)
    }

    fn raw_dealloc(&self, raw: *mut c_void, is_large: bool) {
        // Poison freed memory in debug builds to catch use-after-free bugs
        #[cfg(debug_assertions)]
        {
            if !raw.is_null() {
                let size = if is_large {
                    // For large allocations, poison a reasonable amount
                    64 // Just poison first 64 bytes as a conservative approach
                } else {
                    unsafe { mi_usable_size(raw) }.min(1024) // Limit poisoning to 1KB max
                };

                unsafe {
                    std::ptr::write_bytes(raw as *mut u8, 0xDD, size);
                }
            }
        }

        if is_large {
            unsafe { large_free(raw) };
        } else {
            unsafe { mi_free(raw) };
        }
    }

    /// Allocate and write header in one step. Avoids redundant registry
    /// lookups when the caller already has a GHeap reference (realloc path).
    fn alloc_block(&self, size: usize) -> Option<*mut c_void> {
        let total = size.checked_add(HEADER_SIZE)?;
        let (raw, is_large) = self.raw_alloc_with_fallback(total);
        if raw.is_null() {
            return None;
        }
        Some(unsafe { BlockHeader::write(raw, self as *const GHeap as *mut c_void, is_large, size) })
    }
}

// ============================================================================
// Registry
// ============================================================================

// Wrapper for *const GHeap that implements Send and Sync
// This is safe because we ensure the pointed-to data lives for the program lifetime
#[repr(transparent)]
#[derive(Copy, Clone)]
struct SafeHeapPtr(*const GHeap);

unsafe impl Send for SafeHeapPtr {}
unsafe impl Sync for SafeHeapPtr {}

static REGISTRY: LazyLock<Mutex<std::collections::HashMap<usize, SafeHeapPtr>>> = LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

/// Resolve a game engine heap handle to a stable reference.
/// Pointer is valid for program lifetime — entries are never removed.
fn resolve_heap(handle: *mut c_void) -> &'static GHeap {
    let key = handle as usize;

    // Fast path: lock, lookup, unlock
    if let Some(heap_ptr) = {
        let registry = REGISTRY.lock();
        registry.get(&key).copied().map(|SafeHeapPtr(ptr)| ptr)
    } {
        return unsafe { std::mem::transmute::<&GHeap, &GHeap>(&*heap_ptr) };
    }

    // Slow path: allocate heap outside lock to avoid reentrancy
    info!("new heap for handle {key:#x}");
    let heap = Box::new(GHeap::new());
    let heap_ptr = Box::leak(heap) as *const GHeap;

    // Insert the heap pointer into the registry, handling potential race condition
    let mut registry = REGISTRY.lock();
    if let Some(SafeHeapPtr(existing_ptr)) = registry.get(&key) {
        // Another thread created the heap, return theirs and drop our heap
        std::mem::drop(unsafe { Box::from_raw(heap_ptr as *mut GHeap) });
        return unsafe { std::mem::transmute::<&*const GHeap, &GHeap>(existing_ptr) };
    } else {
        registry.insert(key, SafeHeapPtr(heap_ptr));
    }

    unsafe { std::mem::transmute(&*heap_ptr) }
}

// ============================================================================
// Public API — called by game engine hooks
// ============================================================================

pub fn gheap_alloc(handle: *mut c_void, size: usize) -> *mut c_void {
    if handle.is_null() || size == 0 {
        return null_mut();
    }

    let total = match size.checked_add(HEADER_SIZE) {
        Some(t) => t,
        None => {
            warn!("alloc: size overflow ({size} + {HEADER_SIZE})");
            return null_mut();
        }
    };

    let heap = resolve_heap(handle);
    let (raw, is_large) = heap.raw_alloc_with_fallback(total);

    if raw.is_null() {
        warn!("alloc: fallback also failed for {size} bytes");
        return null_mut(); // Only return NULL as last resort
    }

    unsafe { BlockHeader::write(raw, handle, is_large, size) }
}

pub fn gheap_free(_handle: *mut c_void, ptr: *mut c_void) -> bool {
    if ptr.is_null() {
        return true;
    }

    let header = match unsafe { BlockHeader::from_payload(ptr) } {
        Some(h) => h,
        None => {
            trace!("free: foreign pointer {ptr:?}");
            // For foreign pointers (CRT/vanilla heap allocations), return false
            // to indicate that this pointer was not allocated by our system.
            // The caller should delegate to the original game's free function.
            return false;
        }
    };

    // Trust the heap stored at allocation time, not the engine's handle —
    // the engine passes mismatched handles during level transitions.
    let meta = unsafe { BlockHeader::take(header) };
    let heap = resolve_heap(meta.handle as *mut c_void);
    heap.raw_dealloc(meta.raw, meta.is_large);
    true
}

pub fn gheap_realloc(handle: *mut c_void, ptr: *mut c_void, size: usize) -> Option<*mut c_void> {
    if ptr.is_null() {
        return Some(gheap_alloc(handle, size));
    }
    if size == 0 {
        gheap_free(handle, ptr);
        return Some(null_mut());
    }

    let header = unsafe { BlockHeader::from_payload(ptr) }?;
    let meta = unsafe { BlockHeader::peek(header) };
    let old_heap = resolve_heap(meta.handle as *mut c_void);

    // In-place when new size fits existing capacity
    let capacity = block_capacity(meta.raw, meta.is_large, meta.payload_size);
    if size <= capacity {
        return Some(ptr);
    }

    // Use the engine's handle for the new allocation to respect its memory
    // context. Fall back to the block's own heap if handle is null.
    let target: &GHeap = if !handle.is_null() {
        resolve_heap(handle)
    } else {
        debug!("realloc: null handle, using block's own heap");
        old_heap
    };

    let new_ptr = target.alloc_block(size)?;
    let copy_len = capacity.min(size);
    unsafe { copy_nonoverlapping(ptr as *const u8, new_ptr as *mut u8, copy_len) };

    // Free old block through its original heap
    let old_meta = unsafe { BlockHeader::take(header) };
    old_heap.raw_dealloc(old_meta.raw, old_meta.is_large);
    Some(new_ptr)
}

pub fn gheap_msize(_handle: *mut c_void, ptr: *mut c_void) -> Option<usize> {
    if ptr.is_null() {
        return None;
    }
    let header = unsafe { BlockHeader::from_payload(ptr)? };
    let meta = unsafe { BlockHeader::peek(header) };
    Some(block_capacity(meta.raw, meta.is_large, meta.payload_size))
}

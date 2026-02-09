use libc::c_void;
use libmimalloc::*;
use log::{debug, info, trace, warn};
use scc::HashMap;
use std::ptr::{self, copy_nonoverlapping, null_mut};
use std::sync::LazyLock;
use windows::Win32::System::Memory::PAGE_READWRITE;

// Import VirtualAlloc/VirtualFree wrappers from libpsycho
use libpsycho::os::windows::winapi::{
    AllocationType, FreeType, virtual_alloc, virtual_free,
};

// ============================================================================
// Constants
// ============================================================================

const MAGIC: u32 = 0xDEAD_C0DE;
const CHECK_SALT: u16 = 0xCAFE;

const HEADER_SIZE: usize = size_of::<BlockHeader>();
const HEADER_ALIGN: usize = align_of::<BlockHeader>();

/// Buckets: 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192.
const BUCKET_COUNT: usize = 9;
const BUCKET_MIN: usize = 32;
const BUCKET_MAX: usize = BUCKET_MIN << (BUCKET_COUNT - 1);
const NO_BUCKET: u16 = 0xFFFF;

// Threshold for large allocations that should bypass mimalloc
const LARGE_ALLOC_THRESHOLD: usize = 1 * 1024 * 1024; // 1 MB

// Flags for BlockHeader
const FLAG_LARGE: u16 = 0x1;

// On 32-bit systems: header is 16 bytes
// On 64-bit systems: header is 20 bytes (magic:4 + flags:2 + check:2 + size:4 + heap_key:8)
// Since this is for 32-bit Fallout NV, we expect the header to be 16 bytes
#[cfg(all(target_pointer_width = "32", debug_assertions))]
const _: () = assert!(HEADER_SIZE == 16);
#[cfg(all(target_pointer_width = "64", debug_assertions))]
const _: () = assert!(HEADER_SIZE == 20);

const _: () = assert!(HEADER_ALIGN == 16);

// ============================================================================
// Large allocation functions
// ============================================================================

unsafe fn large_alloc(size: usize) -> *mut c_void {
    match unsafe {
        virtual_alloc(
            None, // address
            size,
            AllocationType::CommitReserve,
            PAGE_READWRITE,
        )
    } {
        Ok(ptr) => ptr,
        Err(_) => null_mut(), // Return null on error
    }
}

unsafe fn large_free(ptr: *mut c_void) {
    let _ = unsafe { virtual_free(ptr, FreeType::Release) }; // Ignore error on free
}

// ============================================================================
// Block Header — 16 bytes, prepended to every allocation
// ============================================================================

/// `[BlockHeader 16B | payload 16B-aligned]`
///
/// Only the first 16 bytes are ours. The payload starts at `raw + 16`
/// and is what the game engine sees. Because the header is exactly 16 bytes,
/// there is no overlap — all fields are preserved while the block is alive.
///
/// Validation: primary magic (32-bit) + integrity check (16-bit) = 48 bits.
/// False positive rate per foreign pointer: ~1 in 2^48.
#[repr(C, align(16))]
struct BlockHeader {
    magic: u32,
    flags: u16, // FLAG_LARGE | FLAG_BUCKETED
    check: u16,
    heap: *const GHeap, // Store the heap pointer (4 bytes on 32-bit, 8 bytes on 64-bit)
    size: u32, // Size of the allocation (for large allocations)
}

// On 64-bit platforms, the header will be 20 bytes, which breaks the design assumption.
// To maintain 16 bytes on both platforms, we need to adjust the structure.
// Since this is for 32-bit Fallout NV, we'll keep the current design but acknowledge
// that it's optimized for 32-bit systems.

unsafe impl Send for BlockHeader {}
unsafe impl Sync for BlockHeader {}

/// Metadata extracted from a header before invalidation.
struct BlockMeta {
    raw: *mut c_void,
    heap: *const GHeap,
    is_large: bool,
    size: u32,
}

#[inline(always)]
fn make_check(heap: *const GHeap, flags: u16) -> u16 {
    let a = heap as usize;
    // Include more bits from the heap address and the flags for stronger validation
    ((a >> 4) as u16) ^ ((a >> 16) as u16) ^ ((a >> 20) as u16) ^ flags ^ CHECK_SALT
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
        if addr < HEADER_SIZE || !addr.is_multiple_of(HEADER_ALIGN) {
            return None;
        }

        let header = (addr - HEADER_SIZE) as *mut Self;
        let h = unsafe { &*header };

        if h.magic != MAGIC {
            return None;
        }
        if h.check != make_check(h.heap, h.flags) {
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
    unsafe fn write(raw: *mut c_void, heap: *const GHeap, is_large: bool, size: usize) -> *mut c_void {
        unsafe {
            let flags = if is_large { FLAG_LARGE } else { 0 };
            ptr::write(
                raw as *mut Self,
                BlockHeader {
                    magic: MAGIC,
                    flags,
                    check: make_check(heap, flags),
                    heap,
                    size: size as u32, // Store the total size
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
            heap: h.heap,
            is_large: (h.flags & FLAG_LARGE) != 0,
            size: h.size,
        };
        h.magic = 0;
        meta
    }

    /// Read metadata without invalidating (realloc in-place check).
    unsafe fn peek(header: *mut Self) -> BlockMeta {
        let h = unsafe { &*header };
        BlockMeta {
            raw: header as *mut c_void,
            heap: h.heap,
            is_large: (h.flags & FLAG_LARGE) != 0,
            size: h.size,
        }
    }
}

// ============================================================================
// Bucket math
// ============================================================================

/// Map total size (header + payload) → bucket index.
#[inline(always)]
fn bucket_for_size(total: usize) -> Option<usize> {
    if !(BUCKET_MIN..=BUCKET_MAX).contains(&total) {
        return None;
    }

    // Calculate the next power of 2 that can hold the total size
    let required_size = total.max(BUCKET_MIN).next_power_of_two();

    // Calculate the bucket index: 32->0, 64->1, 128->2, etc.
    let bucket_idx = (required_size / BUCKET_MIN).trailing_zeros() as usize;

    if bucket_idx < BUCKET_COUNT {
        Some(bucket_idx)
    } else {
        None
    }
}

#[inline(always)]
fn bucket_alloc_size(idx: usize) -> usize {
    BUCKET_MIN << idx
}

/// Payload capacity for a given block. For large allocations, we use the stored size.
/// For small allocations, we use mi_usable_size to get the actual capacity.
#[inline]
fn block_capacity(raw: *mut c_void, is_large: bool, stored_size: u32) -> usize {
    if is_large {
        // For large allocations, use the stored size from the header
        (stored_size as usize).saturating_sub(HEADER_SIZE)
    } else {
        // For small allocations, use mi_usable_size to get actual capacity
        unsafe { mi_usable_size(raw) }.saturating_sub(HEADER_SIZE)
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

    fn raw_alloc_with_fallback(&self, total: usize, _bucket: Option<usize>) -> (*mut c_void, bool) {
        // Use large allocation for objects >= 1MB, and avoid bucketing for anything above ~64KB
        let mut is_large = total >= LARGE_ALLOC_THRESHOLD;
        let mut raw = if is_large {
            unsafe { large_alloc(total) }
        } else {
            // For small allocations, use mimalloc
            unsafe { mi_malloc_aligned(total, HEADER_ALIGN) }
        };

        if raw.is_null() {
            warn!("raw_alloc: primary backing returned null for {total} bytes, attempting fallback");
            // Fallback: try opposite allocation method
            if is_large {
                // Already tried large alloc, try mimalloc as fallback
                raw = unsafe { mi_malloc_aligned(total, HEADER_ALIGN) };
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
        let (raw, is_large) = self.raw_alloc_with_fallback(total, None); // bucket parameter is no longer used
        if raw.is_null() {
            return None;
        }
        Some(unsafe { BlockHeader::write(raw, self as *const GHeap, is_large, total) })
    }
}

// ============================================================================
// Registry
// ============================================================================

use std::sync::atomic::{AtomicU32, Ordering};

static REGISTRY: LazyLock<HashMap<usize, Box<GHeap>>> = LazyLock::new(HashMap::default);
static HEAP_INDEX_COUNTER: AtomicU32 = AtomicU32::new(1); // Start from 1 to avoid 0 as null

/// Resolve a game engine heap handle to a stable reference.
/// Pointer is valid for program lifetime — entries are never removed.
fn resolve_heap(handle: *mut c_void) -> &'static GHeap {
    let key = handle as usize;

    // Hot path
    if let Some(entry) = REGISTRY.get_sync(&key) {
        return unsafe { &*(&**entry as *const GHeap) };
    }

    // Cold path — first allocation on this handle
    info!("new heap for handle {key:#x}");
    let occupied = REGISTRY
        .entry_sync(key)
        .or_insert_with(|| Box::new(GHeap::new()));

    unsafe { &*(&**occupied.get() as *const GHeap) }
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
    let (raw, mut is_large) = heap.raw_alloc_with_fallback(total, None); // bucket parameter is no longer used

    if raw.is_null() {
        warn!("alloc: fallback also failed for {size} bytes");
        return null_mut(); // Only return NULL as last resort
    }

    unsafe { BlockHeader::write(raw, heap as *const GHeap, is_large, total) }
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
    let heap = unsafe { &*meta.heap };
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
    let old_heap = unsafe { &*meta.heap };

    // In-place when new size fits existing capacity
    let capacity = block_capacity(meta.raw, meta.is_large, meta.size);
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
    Some(block_capacity(meta.raw, meta.is_large, meta.size))
}

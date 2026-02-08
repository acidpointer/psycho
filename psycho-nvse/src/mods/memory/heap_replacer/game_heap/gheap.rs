use libc::c_void;
use libmimalloc::heap::MiHeap;
use libmimalloc::*;
use log::{debug, info, trace, warn};
use scc::HashMap;
use std::ptr::{self, copy_nonoverlapping, null_mut};
use std::sync::{LazyLock, Mutex, TryLockError};

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
const BUCKET_DEPTH: usize = 48;
const NO_BUCKET: u16 = 0xFFFF;

const _: () = assert!(HEADER_SIZE == 16);
const _: () = assert!(HEADER_ALIGN == 16);

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
    bucket_idx: u16,
    check: u16,
    heap: *const GHeap,
}

unsafe impl Send for BlockHeader {}
unsafe impl Sync for BlockHeader {}

/// Metadata extracted from a header before invalidation.
struct BlockMeta {
    raw: *mut c_void,
    heap: *const GHeap,
    bucket: Option<usize>,
}

#[inline(always)]
fn make_check(heap: *const GHeap) -> u16 {
    let a = heap as usize;
    ((a >> 4) as u16) ^ ((a >> 20) as u16) ^ CHECK_SALT
}

#[inline(always)]
fn decode_bucket(idx: u16) -> Option<usize> {
    if idx == NO_BUCKET { None } else { Some(idx as usize) }
}

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
        if h.check != make_check(h.heap) {
            warn!("corrupted header at {payload:?}: magic OK, check mismatch");
            return None;
        }
        if h.bucket_idx != NO_BUCKET && h.bucket_idx as usize >= BUCKET_COUNT {
            warn!("corrupted header at {payload:?}: bad bucket_idx={}", h.bucket_idx);
            return None;
        }

        Some(header)
    }

    #[inline(always)]
    unsafe fn to_payload(raw: *mut c_void) -> *mut c_void {
        unsafe { (raw as *mut u8).add(HEADER_SIZE) as *mut c_void }
    }

    /// Write a fresh header at `raw`, return the payload pointer.
    unsafe fn write(
        raw: *mut c_void,
        heap: *const GHeap,
        bucket: Option<usize>,
    ) -> *mut c_void {
        unsafe {
            ptr::write(
                raw as *mut Self,
                BlockHeader {
                    magic: MAGIC,
                    bucket_idx: bucket.map(|i| i as u16).unwrap_or(NO_BUCKET),
                    check: make_check(heap),
                    heap,
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
            bucket: decode_bucket(h.bucket_idx),
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
            bucket: decode_bucket(h.bucket_idx),
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
    let order = (usize::BITS - (total - 1).leading_zeros()) as usize;
    order.checked_sub(5).filter(|&i| i < BUCKET_COUNT)
}

#[inline(always)]
fn bucket_alloc_size(idx: usize) -> usize {
    BUCKET_MIN << idx
}

/// Payload capacity for a given block. Only calls `mi_usable_size` on
/// non-bucketed blocks (which are guaranteed to be our mimalloc allocations).
#[inline]
fn block_capacity(raw: *mut c_void, bucket: Option<usize>) -> usize {
    match bucket {
        Some(idx) => bucket_alloc_size(idx) - HEADER_SIZE,
        None => unsafe { mi_usable_size(raw) }.saturating_sub(HEADER_SIZE),
    }
}

// ============================================================================
// BucketStack — fixed-capacity, zero-heap-alloc, inline LIFO
// ============================================================================

/// Inline array + length. No heap allocation on construction — critical
/// because `GHeap::new()` runs inside the registry's insert closure where
/// reentrant allocator calls would deadlock the engine's heap hooks.
struct BucketStack {
    items: [*mut c_void; BUCKET_DEPTH],
    len: usize,
}

unsafe impl Send for BucketStack {}

impl BucketStack {
    const fn new() -> Self {
        Self {
            items: [null_mut(); BUCKET_DEPTH],
            len: 0,
        }
    }

    fn push(&mut self, ptr: *mut c_void) -> bool {
        if self.len >= BUCKET_DEPTH {
            return false;
        }
        self.items[self.len] = ptr;
        self.len += 1;
        true
    }

    fn pop(&mut self) -> Option<*mut c_void> {
        if self.len == 0 || self.len > BUCKET_DEPTH {
            self.len = 0; // Recover from corruption
            return None;
        }
        self.len -= 1;
        let ptr = self.items[self.len];
        self.items[self.len] = null_mut();
        Some(ptr)
    }

    fn clear(&mut self) {
        self.len = 0;
    }
}

// ============================================================================
// GHeap — per-handle allocator backed by mimalloc
// ============================================================================

pub struct GHeap {
    mi: MiHeap,
    /// Per-bucket Mutex with `try_lock`: non-blocking on contention (falls
    /// through to mimalloc), recovers from poison (clears cache).
    buckets: [Mutex<BucketStack>; BUCKET_COUNT],
}

unsafe impl Send for GHeap {}
unsafe impl Sync for GHeap {}

impl GHeap {
    fn new() -> Self {
        Self {
            mi: MiHeap::new(),
            buckets: std::array::from_fn(|_| Mutex::new(BucketStack::new())),
        }
    }

    fn raw_alloc(&self, total: usize, bucket: Option<usize>) -> *mut c_void {
        if let Some(idx) = bucket
            && let Some(cached) = self.bucket_pop(idx) {
                return cached;
            }
        let size = bucket.map(bucket_alloc_size).unwrap_or(total);
        self.mi.malloc_aligned(size, HEADER_ALIGN)
    }

    fn raw_dealloc(&self, raw: *mut c_void, bucket: Option<usize>) {
        if let Some(idx) = bucket
            && self.bucket_push(idx, raw) {
                return;
            }
        unsafe { mi_free(raw) };
    }

    /// Allocate and write header in one step. Avoids redundant registry
    /// lookups when the caller already has a GHeap reference (realloc path).
    fn alloc_block(&self, size: usize) -> Option<*mut c_void> {
        let total = size.checked_add(HEADER_SIZE)?;
        let bucket = bucket_for_size(total);
        let raw = self.raw_alloc(total, bucket);
        if raw.is_null() {
            return None;
        }
        Some(unsafe { BlockHeader::write(raw, self as *const GHeap, bucket) })
    }

    fn bucket_pop(&self, idx: usize) -> Option<*mut c_void> {
        match self.buckets[idx].try_lock() {
            Ok(mut g) => g.pop(),
            Err(TryLockError::Poisoned(e)) => {
                warn!("bucket {idx}: recovering poisoned mutex");
                e.into_inner().clear();
                None
            }
            Err(TryLockError::WouldBlock) => None,
        }
    }

    fn bucket_push(&self, idx: usize, ptr: *mut c_void) -> bool {
        match self.buckets[idx].try_lock() {
            Ok(mut g) => g.push(ptr),
            Err(TryLockError::Poisoned(e)) => {
                warn!("bucket {idx}: recovering poisoned mutex on push");
                let mut g = e.into_inner();
                g.clear();
                g.push(ptr)
            }
            Err(TryLockError::WouldBlock) => false,
        }
    }
}

// ============================================================================
// Registry
// ============================================================================

static REGISTRY: LazyLock<HashMap<usize, Box<GHeap>>> = LazyLock::new(HashMap::default);

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
    let bucket = bucket_for_size(total);
    let raw = heap.raw_alloc(total, bucket);

    if raw.is_null() {
        warn!("alloc: backing returned null for {size} bytes");
        return null_mut();
    }

    unsafe { BlockHeader::write(raw, heap as *const GHeap, bucket) }
}

pub fn gheap_free(_handle: *mut c_void, ptr: *mut c_void) -> bool {
    if ptr.is_null() {
        return true;
    }

    let header = match unsafe { BlockHeader::from_payload(ptr) } {
        Some(h) => h,
        None => {
            trace!("free: foreign pointer {ptr:?}");
            return false;
        }
    };

    // Trust the heap stored at allocation time, not the engine's handle —
    // the engine passes mismatched handles during level transitions.
    let meta = unsafe { BlockHeader::take(header) };
    let heap = unsafe { &*meta.heap };
    heap.raw_dealloc(meta.raw, meta.bucket);
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
    let capacity = block_capacity(meta.raw, meta.bucket);
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
    old_heap.raw_dealloc(old_meta.raw, old_meta.bucket);
    Some(new_ptr)
}

pub fn gheap_msize(_handle: *mut c_void, ptr: *mut c_void) -> Option<usize> {
    if ptr.is_null() {
        return None;
    }
    let header = unsafe { BlockHeader::from_payload(ptr)? };
    let meta = unsafe { BlockHeader::peek(header) };
    Some(block_capacity(meta.raw, meta.bucket))
}
use libc::c_void;
use libmimalloc::heap::MiHeap;
use libmimalloc::*;
use scc::HashMap;
use std::ptr::{copy_nonoverlapping, null_mut};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, LazyLock};

// ============================================================================
// CONSTANTS & TYPES
// ============================================================================

const MAGIC: u32 = 0xDEADC0DE;
const HEADER_SIZE: usize = 16;
const BUCKET_COUNT: usize = 9;

#[repr(C, align(16))]
struct BlockHeader {
    magic: u32,
    bucket_idx: u16,
    _reserved: u16,
    // We store a raw pointer, but we manually increment the Arc ref-count
    // when writing this header and decrement it when freeing.
    parent: *const GHeap,
    usable_size: usize,
}

static REGISTRY: LazyLock<HashMap<usize, Arc<GHeap>>> = LazyLock::new(HashMap::default);

// ============================================================================
// HELPER: POINTER & HEADER MATH (The "Unsafe" Layer)
// ============================================================================

impl BlockHeader {
    #[inline(always)]
    unsafe fn from_payload<'a>(ptr: *mut c_void) -> Option<&'a mut Self> {
        let addr = ptr as usize;
        // If not 16-byte aligned, it's 100% not our allocation.
        if addr < HEADER_SIZE || !addr.is_multiple_of(16) {
            return None;
        }

        let header = unsafe { &mut *((addr - HEADER_SIZE) as *mut Self) };
        if header.magic == MAGIC {
            Some(header)
        } else {
            None
        }
    }

    #[inline(always)]
    unsafe fn to_payload(header_ptr: *mut Self) -> *mut c_void {
        (unsafe { (header_ptr as *mut u8).add(HEADER_SIZE) }) as *mut c_void
    }

    #[inline(always)]
    fn is_valid(&self, expected_heap: *const GHeap) -> bool {
        self.magic == MAGIC && self.parent == expected_heap
    }

    /// SAFETY: Reconstructs ownership. Must be called exactly once per block destruction.
    unsafe fn take_heap_ownership(&mut self) -> Arc<GHeap> {
        self.magic = 0; // Immediate invalidation to prevent double-frees
        unsafe { Arc::from_raw(self.parent) }
    }

    /// SAFETY: Borrows the heap reference without modifying the ref-count.
    unsafe fn get_heap_ref(&self) -> &GHeap {
        unsafe { &*self.parent }
    }
}

// ============================================================================
// ENTITY: GHeap (The Logic Layer)
// ============================================================================

pub struct GHeap {
    mi_heap: MiHeap,
    buckets: [AtomicPtr<c_void>; BUCKET_COUNT],
}

impl GHeap {
    pub fn new() -> Self {
        Self {
            mi_heap: MiHeap::new(),
            buckets: [const { AtomicPtr::new(null_mut()) }; BUCKET_COUNT],
        }
    }

    pub fn allocate(&self, size: usize) -> (*mut c_void, Option<usize>) {
        let total = size + HEADER_SIZE;
        let b_idx = self.get_bucket_idx(total);

        let raw = b_idx
            .and_then(|i| self.pop_bucket(i))
            .unwrap_or_else(|| self.alloc_from_backing(total, b_idx));

        (raw, b_idx)
    }

    pub fn deallocate(&self, payload: *mut c_void) -> bool {
        unsafe {
            // Unwrap the Option returned by from_payload
            if let Some(header) = BlockHeader::from_payload(payload) {
                if !header.is_valid(self) {
                    return false;
                }

                let b_idx = header.bucket_idx;
                header.magic = 0; // Invalidate

                let raw = (header as *mut BlockHeader) as *mut c_void;
                if b_idx != 0xFFFF {
                    self.push_bucket(b_idx as usize, raw);
                } else {
                    mi_free(raw);
                }
                true
            } else {
                false
            }
        }
    }

    // --- Private Helpers ---

    #[inline(always)]
    fn get_bucket_idx(&self, total: usize) -> Option<usize> {
        if !(32..=8192).contains(&total) {
            return None;
        }
        let idx = (usize::BITS - (total - 1).leading_zeros()) as usize;
        if idx >= 5 { Some(idx - 5) } else { None }
    }

    fn pop_bucket(&self, idx: usize) -> Option<*mut c_void> {
        let mut head = self.buckets[idx].load(Ordering::Acquire);
        while !head.is_null() {
            let next = unsafe { *(head as *mut *mut c_void) };
            if self.buckets[idx]
                .compare_exchange_weak(head, next, Ordering::Release, Ordering::Acquire)
                .is_ok()
            {
                return Some(head);
            }
            head = self.buckets[idx].load(Ordering::Acquire);
        }
        None
    }

    fn push_bucket(&self, idx: usize, raw: *mut c_void) {
        let mut head = self.buckets[idx].load(Ordering::Acquire);
        loop {
            unsafe {
                *(raw as *mut *mut c_void) = head;
            }
            match self.buckets[idx].compare_exchange_weak(
                head,
                raw,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(updated) => head = updated,
            }
        }
    }

    fn alloc_from_backing(&self, size: usize, b_idx: Option<usize>) -> *mut c_void {
        let actual_size = b_idx.map(|i| 32 << i).unwrap_or(size);
        self.mi_heap.malloc_aligned(actual_size, 16)
    }
    unsafe fn initialize_at(
        heap: Arc<GHeap>,
        raw_ptr: *mut c_void,
        b_idx: Option<usize>,
        usable_size: usize,
    ) -> *mut c_void {
        let header_ptr = raw_ptr as *mut BlockHeader;

        // Use ptr::write to avoid reading uninitialized memory
        unsafe {
            header_ptr.write(BlockHeader {
                magic: MAGIC,
                bucket_idx: b_idx.map(|i| i as u16).unwrap_or(0xFFFF),
                _reserved: 0,
                // Consumes the Arc and turns it into a raw pointer
                parent: Arc::into_raw(heap),
                usable_size,
            })
        };

        BlockHeader::to_payload(header_ptr)
    }

    unsafe fn write_header(
        heap_arc: Arc<GHeap>,
        raw: *mut c_void,
        b_idx: Option<usize>,
        size: usize,
    ) -> *mut c_void {
        let h = raw as *mut BlockHeader;
        (*h).magic = MAGIC;
        (*h).bucket_idx = b_idx.map(|i| i as u16).unwrap_or(0xFFFF);

        // This effectively "pins" the GHeap until gheap_free calls Arc::from_raw
        let heap_ptr = Arc::into_raw(heap_arc);
        (*h).parent = heap_ptr;
        (*h).usable_size = size;

        BlockHeader::to_payload(h)
    }
}

// ============================================================================
// DISPATCHER: PUBLIC API (The Entry Layer)
// ============================================================================

#[inline(always)]
fn get_heap(handle: *mut c_void) -> Arc<GHeap> {
    let key = handle as usize;

    // Use get_sync first for the hot path (most common)
    if let Some(h) = REGISTRY.get_sync(&key) {
        return Arc::clone(&*h);
    }

    // Atomic insertion: only one thread will succeed in creating the GHeap
    let _ = REGISTRY.entry_sync(key).or_insert(Arc::new(GHeap::new()));

    // Final retrieval
    REGISTRY
        .get_sync(&key)
        .map(|h| Arc::clone(&*h))
        .expect("Heap lost during fast travel")
}

pub fn gheap_alloc(handle: *mut c_void, size: usize) -> *mut c_void {
    if handle.is_null() || size == 0 {
        return null_mut();
    }

    let heap_arc = get_heap(handle);
    let (raw, b_idx) = heap_arc.allocate(size);

    if raw.is_null() {
        return null_mut();
    }

    unsafe { GHeap::write_header(heap_arc, raw, b_idx, size) }
}

pub fn gheap_free(_heap_ptr: *mut c_void, ptr: *mut c_void) -> bool {
    if ptr.is_null() { return true; }

    unsafe {
        let header = match BlockHeader::from_payload(ptr) {
            Some(h) => h,
            None => return false,
        };

        // Transition ownership back to Rust's Arc
        let heap_arc = header.take_heap_ownership();
        heap_arc.deallocate(ptr) 
        // heap_arc drops here, correctly decrementing the counter
    }
}

pub fn gheap_realloc(heap_ptr: *mut c_void, ptr: *mut c_void, size: usize) -> Option<*mut c_void> {
    if ptr.is_null() { return Some(gheap_alloc(heap_ptr, size)); }

    unsafe {
        let header = BlockHeader::from_payload(ptr)?;
        let old_size = header.usable_size;
        
        // Peek at the heap without taking ownership yet
        let actual_heap = header.get_heap_ref();

        // 1. Check if we can keep the current block
        let b_idx = header.bucket_idx;
        let capacity = if b_idx != 0xFFFF {
            (32 << b_idx) - HEADER_SIZE
        } else {
            mi_usable_size((header as *mut BlockHeader) as *mut c_void) - HEADER_SIZE
        };

        if size <= capacity {
            header.usable_size = size;
            return Some(ptr);
        }

        // 2. Migration path: Allocate new, Copy, then Free old
        let new_ptr = gheap_alloc(heap_ptr, size);
        if !new_ptr.is_null() {
            copy_nonoverlapping(ptr, new_ptr, old_size);
            gheap_free(null_mut(), ptr); // Cleanly handles Arc decrement
            return Some(new_ptr);
        }
    }
    None
}

pub fn gheap_msize(_heap_ptr: *mut c_void, ptr: *mut c_void) -> Option<usize> {
    if ptr.is_null() {
        return None;
    }
    unsafe {
        // Ignore heap_ptr, just validate the header
        if let Some(header) = BlockHeader::from_payload(ptr) {
            return Some(header.usable_size);
        }
    }
    None
}

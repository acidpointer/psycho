//! Region
//! This is very basic yet important building block for
//! scrap heap allocator for Fallout: New Vegas.

use libc::c_void;
use libmimalloc::heap::MiHeap;
use libpsycho::common::align_up;
use std::{
    ptr::NonNull,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
};

use super::stats::AllocatorStats;

/// Shift amount to convert addresses to page numbers (4096-byte pages)
const PAGE_SHIFT: usize = 12;

pub struct Region {
    /// Start address of the allocated memory block
    start: NonNull<u8>,

    /// Total capacity of the region in bytes
    capacity: usize,

    /// Current allocation offset within the region
    offset: AtomicUsize,

    /// Address from which region starts
    start_page: usize,

    /// Address from which region ends
    end_page: usize,

    /// Arced statistics to track allocations
    stats: Arc<AllocatorStats>,

    /// Flag which shows if region was purged
    is_purged: AtomicBool,
}

// Safety: Safe, because all inner state is atomic
unsafe impl Send for Region {}
unsafe impl Sync for Region {}

impl Region {
    /// Creates a new memory region backed by mimalloc.
    ///
    /// # Arguments
    /// * `capacity` - Size of the region to allocate
    /// * `align` - Required alignment for the region
    ///
    /// # Returns
    /// `Some(Region)` if allocation succeeded, `None` otherwise
    pub fn new(
        capacity: usize,
        align: usize,
        mi_heap: Arc<MiHeap>,
        stats: Arc<AllocatorStats>,
    ) -> Option<Self> {
        let ptr = mi_heap.malloc_aligned(capacity, align);
        let start = NonNull::new(ptr as *mut u8)?;

        stats.add_total_alloc_mem(capacity as u64);

        let start_ptr = start.as_ptr() as usize;

        Some(Self {
            start,
            capacity,
            offset: AtomicUsize::new(0),
            start_page: start_ptr >> PAGE_SHIFT,
            end_page: (start_ptr + capacity) >> PAGE_SHIFT,
            stats,
            is_purged: AtomicBool::new(false),
        })
    }

    /// Check if allocation possible on this region
    ///
    /// # Arguments
    /// * `size` - Size of allocation in bytes
    /// * `align` - Required alignment for allocation
    /// # Returns
    /// `true` if allocation is possible
    #[inline]
    pub fn is_allocate_possible(&self, size: usize, align: usize) -> bool {
        let current_offset = self.offset.load(Ordering::Relaxed);
        let start_addr = self.start.as_ptr() as usize;

        // 1. Calculate the earliest possible data address
        // We must leave at least 4 bytes for the header.
        let min_data_addr = start_addr + current_offset + 4;

        // 2. Align the data pointer to the requested alignment
        let data_addr = align_up(min_data_addr, align);

        let requested_end = (data_addr - start_addr) + size;

        requested_end <= self.capacity
    }

    /// Performs a bump-pointer allocation within the region.
    ///
    /// # Arguments
    /// * `size` - Size of the allocation in bytes
    /// * `align` - Required alignment for the allocation
    ///
    /// # Returns
    /// `Some(NonNull<u8>)` if allocation succeeded, `None` if region is full
    #[inline]
    pub fn allocate(&self, size: usize, align: usize) -> Option<NonNull<c_void>> {
        // We reserve the maximum possible space we might need:
        // size + align + 4 (header)
        let reservation = size + align + 4;

        // Single atomic operation. No loop. No contention retries.
        let old_offset = self.offset.fetch_add(reservation, Ordering::Relaxed);

        if old_offset + reservation > self.capacity {
            // We over-allocated or the region is full.
            // Note: This technically "wastes" the reservation if we fail,
            // but for a 128KB region, it's better than stuttering.
            return None;
        }

        let start_addr = self.start.as_ptr() as usize;

        // Now we calculate the actual pointer within our RESERVED block
        let min_data_addr = start_addr + old_offset + 4;
        let data_addr = align_up(min_data_addr, align);
        let header_addr = data_addr - 4;

        unsafe {
            let size_ptr = header_addr as *mut AtomicU32;
            (*size_ptr).store(size as u32, Ordering::Relaxed);
        }

        NonNull::new(data_addr as *mut c_void)
    }

    // pub fn allocate(&self, size: usize, align: usize) -> Option<NonNull<c_void>> {
    //     let start_addr = self.start.as_ptr() as usize;
    //     // Relaxed: CAS loop provides synchronization, no need for Acquire barrier
    //     let mut current_offset = self.offset.load(Ordering::Relaxed);

    //     loop {
    //         // 1. Calculate the earliest possible data address
    //         // We must leave at least 4 bytes for the header.
    //         let min_data_addr = start_addr + current_offset + 4;

    //         // 2. Align the data pointer to the requested alignment
    //         let data_addr = align_up(min_data_addr, align);

    //         // 3. The header is NOW guaranteed to be exactly 4 bytes before data
    //         let header_addr = data_addr - 4;

    //         let requested_end = (data_addr - start_addr) + size;

    //         if requested_end > self.capacity {
    //             return None;
    //         }

    //         // Relaxed CAS: faster, no memory barriers needed for bump allocator
    //         // Offset synchronization is sufficient for correctness
    //         match self.offset.compare_exchange_weak(
    //             current_offset,
    //             requested_end, // New offset is the end of the data
    //             Ordering::Relaxed,
    //             Ordering::Relaxed,
    //         ) {
    //             Ok(_) => {
    //                 unsafe {
    //                     let size_ptr = header_addr as *mut AtomicU32;
    //                     // Relaxed: header write doesn't need Release barrier
    //                     (*size_ptr).store(size as u32, Ordering::Relaxed);
    //                 }
    //                 return NonNull::new(data_addr as *mut c_void);
    //             }
    //             Err(next_val) => current_offset = next_val,
    //         }
    //     }
    // }

    /// Attempts to perform LIFO(Last Input First Output) free operation.
    ///
    /// Returns true on success, otherwise returns false.
    #[inline]
    pub fn try_free(&self, ptr: *mut c_void) -> bool {
        let addr = ptr as usize;
        let start_addr = self.start.as_ptr() as usize;

        // 1. Boundary Check
        if addr < start_addr + 4 || addr >= (start_addr + self.capacity) {
            return false;
        }

        // 2. Read the header safely
        // Use Acquire ordering to synchronize with the Release store in allocate()
        let header_ptr = (addr - 4) as *const AtomicU32;
        let size = unsafe { (*header_ptr).load(Ordering::Acquire) } as usize;

        // 3. Corruption/Sanity Check
        if size == 0 || size > self.capacity {
            return false;
        }

        // 4. LIFO Validation and Atomic Rollback
        let curr_offset = self.offset.load(Ordering::Acquire);

        // Check if this pointer is indeed the 'top' of the stack
        // The current offset must equal: (pointer address - start) + size
        if addr - start_addr + size == curr_offset {
            return self
                .offset
                .compare_exchange(
                    curr_offset,
                    addr - start_addr - 4, // Roll back to before the header
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok();
        }

        false
    }

    /// Check if pointer allocater from this region
    ///
    /// # Arguments
    /// * `ptr` - Pointer which should be checked
    /// # Returns
    /// `true` if `pointer` belongs to this region
    #[allow(dead_code)]
    #[inline]
    pub fn is_our_ptr(&self, ptr: *mut c_void) -> bool {
        let addr = ptr as usize;
        let page = addr >> PAGE_SHIFT;

        (self.start_page <= page) && (page < self.end_page)
    }

    /// Deallocates all memory, making all allocations invalid
    #[inline]
    pub fn purge(&self) {
        self.offset.store(0, Ordering::Release);
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        unsafe {
            libmimalloc::mi_free(self.start.as_ptr() as *mut c_void);
        }

        self.stats.sub_total_alloc_mem(self.capacity as u64);
    }
}

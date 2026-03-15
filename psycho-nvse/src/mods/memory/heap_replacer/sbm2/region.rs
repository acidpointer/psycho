//! Region
//! Lock-free bump-pointer region for the scrap heap allocator.

use libc::c_void;
use libpsycho::common::align_up;
use std::{
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering},
};

use super::stats::AllocatorStats;

pub struct Region {
    /// Start address of the allocated memory block
    start: NonNull<u8>,

    /// Total capacity of the region in bytes
    capacity: usize,

    /// Current allocation offset within the region (atomic for cross-thread access)
    offset: AtomicUsize,

    /// Raw pointer to the shared stats (owned by Runtime, outlives all Regions).
    /// Avoids Arc refcount bump on every region creation.
    stats: *const AllocatorStats,
}

// Safety: All mutable state is atomic. `start` is never mutated after construction.
// `stats` points to an Arc-owned AllocatorStats that outlives all Regions.
unsafe impl Send for Region {}
unsafe impl Sync for Region {}

impl Region {
    /// Creates a new memory region using global `mi_malloc_aligned`.
    ///
    /// # Safety contract on `stats`:
    /// The caller must ensure `stats` points to an AllocatorStats that outlives
    /// this Region. In practice, Runtime owns `Arc<AllocatorStats>` and all
    /// Regions are dropped before Runtime.
    pub fn new(
        capacity: usize,
        align: usize,
        stats: &AllocatorStats,
    ) -> Option<Self> {
        let ptr = unsafe { libmimalloc::mi_malloc_aligned(capacity, align) };
        let start = NonNull::new(ptr as *mut u8)?;

        stats.add_total_alloc_mem(capacity as u64);

        Some(Self {
            start,
            capacity,
            offset: AtomicUsize::new(0),
            stats: stats as *const AllocatorStats,
        })
    }

    /// Lock-free bump-pointer allocation.
    ///
    /// Uses a single `fetch_add` to reserve space atomically.
    /// Concurrent threads can allocate from the same region without locking.
    ///
    /// Reservation uses the tight formula `align_up(size + 4, align)` which
    /// packs consecutive allocations without gaps (each allocation's alignment
    /// padding absorbs the previous one's overflow). The bounds check uses
    /// the exact write range (`data_addr + size`) rather than the reservation,
    /// because the last allocation's footprint can exceed its reservation by
    /// up to `align - 1` bytes (no subsequent allocation to absorb the gap).
    #[inline]
    pub fn allocate(&self, size: usize, align: usize) -> Option<NonNull<c_void>> {
        let reservation = align_up(size + 4, align);

        // Single atomic op. No loop, no contention retries.
        let old_offset = self.offset.fetch_add(reservation, Ordering::Relaxed);

        let start_addr = self.start.as_ptr() as usize;
        let end_addr = start_addr + self.capacity;

        let min_data_addr = start_addr + old_offset + 4;
        let data_addr = align_up(min_data_addr, align);
        let header_addr = data_addr - 4;

        // Exact bounds check: verify header + data fit within the region.
        // This catches both normal exhaustion and the boundary case where
        // alignment padding pushes the write past the reservation range.
        if data_addr + size > end_addr {
            return None;
        }

        unsafe {
            // Write inline size header
            (header_addr as *mut u32).write(size as u32);

            // data_addr is start + non-zero offset, guaranteed non-null
            Some(NonNull::new_unchecked(data_addr as *mut c_void))
        }
    }

    /// Check if pointer was allocated from this region
    #[allow(dead_code)]
    #[inline]
    pub fn is_our_ptr(&self, ptr: *mut c_void) -> bool {
        let addr = ptr as usize;
        let start = self.start.as_ptr() as usize;
        addr >= start && addr < start + self.capacity
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        unsafe {
            libmimalloc::mi_free(self.start.as_ptr() as *mut c_void);
            (*self.stats).sub_total_alloc_mem(self.capacity as u64);
        }
    }
}

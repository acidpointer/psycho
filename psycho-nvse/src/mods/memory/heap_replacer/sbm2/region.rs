//! Lock-free bump-pointer region for the scrap heap allocator.

use libc::c_void;
use std::{
    ptr::NonNull,
    sync::{Arc, atomic::{AtomicUsize, Ordering}},
};

use super::stats::AllocatorStats;

/// Align `addr` up to `align`, returning `None` on overflow.
#[inline(always)]
fn checked_align_up(addr: usize, align: usize) -> Option<usize> {
    let mask = align.wrapping_sub(1);
    addr.checked_add(mask).map(|v| v & !mask)
}

pub struct Region {
    /// Start address of the allocated memory block.
    start: NonNull<u8>,

    /// Total capacity of the region in bytes.
    capacity: usize,

    /// Current allocation offset within the region (atomic for cross-thread access).
    offset: AtomicUsize,

    /// Shared stats, owned by Runtime (outlives all Regions).
    /// Using Arc avoids raw pointer and unsafe Send/Sync impls.
    stats: Arc<AllocatorStats>,
}

// Safety: All mutable state is atomic. `start` is never mutated after construction.
unsafe impl Send for Region {}
unsafe impl Sync for Region {}

impl Region {
    /// Creates a new memory region using global `mi_malloc_aligned`.
    pub fn new(capacity: usize, align: usize, stats: &Arc<AllocatorStats>) -> Option<Self> {
        let ptr = unsafe { libmimalloc::mi_malloc_aligned(capacity, align) };
        let start = NonNull::new(ptr as *mut u8)?;

        stats.add_total_alloc_mem(capacity as u64);

        Some(Self {
            start,
            capacity,
            offset: AtomicUsize::new(0),
            stats: Arc::clone(stats),
        })
    }

    /// Lock-free bump-pointer allocation via CAS loop.
    ///
    /// The offset is only advanced on success - failed allocations (region full
    /// or arithmetic overflow) do NOT leak offset space.
    #[inline]
    pub fn allocate(&self, size: usize, align: usize) -> Option<NonNull<c_void>> {
        let start_addr = self.start.as_ptr() as usize;
        let end_addr = start_addr + self.capacity;

        loop {
            let old_offset = self.offset.load(Ordering::Relaxed);

            // Compute aligned data address with overflow protection.
            let min_data_addr = start_addr.checked_add(old_offset)?.checked_add(4)?;
            let data_addr = checked_align_up(min_data_addr, align)?;

            // Bounds check BEFORE committing.
            let alloc_end = data_addr.checked_add(size)?;
            if alloc_end > end_addr {
                return None;
            }

            // new_offset = actual consumed space from region start.
            // Must use data_addr (which includes alignment padding), NOT a
            // separate reservation calculation. The old code computed
            // reservation = align_up(size + 4, align) independently, which
            // didn't account for padding between old_offset+4 and data_addr.
            // This caused subsequent allocations to overlap previous ones.
            let new_offset = alloc_end - start_addr;

            if self
                .offset
                .compare_exchange_weak(old_offset, new_offset, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                let header_addr = data_addr - 4;
                unsafe {
                    (header_addr as *mut u32).write(size as u32);
                }
                return NonNull::new(data_addr as *mut c_void);
            }
        }
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

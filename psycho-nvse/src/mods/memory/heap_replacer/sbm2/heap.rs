use super::region::Region;
use super::stats::AllocatorStats;
use super::runtime::SeqQueue;

use crossfire::flavor::Queue;
use libc::c_void;
use parking_lot::RwLock;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Region size in bytes
/// Recommended values:
/// * MIN: 128Kb
/// * MAX: 512Kb (extreme)
/// # Notes
/// * `REGION_SIZE` < `128Kb` will lead to crashes!
/// * `REGION_SIZE` > `512Kb` will lead to OOM(Out-Of-Memory)!
const REGION_SIZE: usize = 256 * 1024;

/// Region alignment
const REGION_ALIGN: usize = 16;

pub struct Heap {
    /// Region pool protected by RwLock.
    /// Read lock for allocation (fast path), write lock for new region creation.
    pool: RwLock<Vec<Region>>,

    /// Shared allocator statistics — owned by Runtime, outlives all Heaps.
    stats: Arc<AllocatorStats>,

    /// Live allocation count — only modified after confirmed success
    alloc_count: AtomicUsize,

    /// Whether this heap's ID is already in the GC queue.
    /// Prevents duplicate pushes on rapid alloc/free cycles.
    gc_queued: AtomicBool,

    /// Reference to the shared GC queue
    gc_queue: Arc<SeqQueue<usize>>,

    /// Sheap identity (the sheap_ptr address used as key)
    sheap_id: usize,

    /// Generation counter — incremented on purge to invalidate TLC entries
    generation: AtomicUsize,
}

impl Heap {
    pub fn new(
        sheap_id: usize,
        gc_queue: Arc<SeqQueue<usize>>,
        stats: Arc<AllocatorStats>,
    ) -> Self {
        Self {
            pool: RwLock::new(Vec::with_capacity(8)),
            gc_queue,
            stats,
            alloc_count: AtomicUsize::new(0),
            gc_queued: AtomicBool::new(false),
            sheap_id,
            generation: AtomicUsize::new(0),
        }
    }

    #[inline(always)]
    pub fn get_generation(&self) -> usize {
        self.generation.load(Ordering::Acquire)
    }

    /// Allocates memory from the region pool.
    ///
    /// Fast path: read lock, try last region (lock-free bump inside region).
    /// Slow path: write lock, create new region, allocate from it.
    ///
    /// `alloc_count` is only incremented AFTER confirmed allocation success.
    #[inline]
    pub fn try_alloc(&self, size: usize, align: usize) -> Option<*mut c_void> {
        // Fast path: read lock — allocate from last (newest) region
        {
            let pool = self.pool.read();

            if let Some(last_region) = pool.last()
                && let Some(ptr) = last_region.allocate(size, align)
            {
                self.alloc_count.fetch_add(1, Ordering::Release);
                return Some(ptr.as_ptr());
            }
        }

        // Slow path: write lock — create a new region
        {
            let mut pool = self.pool.write();

            // Re-check: another thread may have pushed a new region
            if let Some(last_region) = pool.last()
                && let Some(ptr) = last_region.allocate(size, align)
            {
                self.alloc_count.fetch_add(1, Ordering::Release);
                return Some(ptr.as_ptr());
            }

            // Oversized allocations get a dedicated region
            let region_capacity = REGION_SIZE.max(size + align + 4);

            // Pass &AllocatorStats — Region stores raw pointer, no Arc clone
            if let Some(region) = Region::new(
                region_capacity,
                REGION_ALIGN,
                &self.stats,
            ) && let Some(ptr) = region.allocate(size, align)
            {
                pool.push(region);
                self.alloc_count.fetch_add(1, Ordering::Release);
                return Some(ptr.as_ptr());
            }
        }

        None
    }

    /// Decrements the allocation count and enqueues for GC if count reaches zero.
    #[inline]
    pub fn free(&self, _ptr: *mut c_void) {
        let prev = self.alloc_count.fetch_sub(1, Ordering::Release);

        // prev is the value BEFORE subtraction, so prev == 1 means new count is 0
        if prev == 1
            && !self.gc_queued.swap(true, Ordering::Acquire)
            && let Err(failed_id) = self.gc_queue.push(self.sheap_id)
        {
            log::error!(
                "heap: free: failed to push sheap_id={:#x} to gc_queue!",
                failed_id
            );
            self.gc_queued.store(false, Ordering::Release);
        }
    }

    /// Purge all regions. Called by game-initiated sheap resets.
    ///
    /// Resets alloc_count and bumps generation to invalidate TLC entries.
    ///
    /// # Warning
    /// All allocations from this heap become invalid after this call.
    #[inline]
    pub fn purge(&self) -> usize {
        let mut pool = self.pool.write();

        let old_len = pool.len();
        pool.clear();

        // Reset state
        self.alloc_count.store(0, Ordering::Release);
        self.gc_queued.store(false, Ordering::Release);
        self.generation.fetch_add(1, Ordering::Release);

        old_len
    }

    /// GC-initiated purge. Only purges if alloc_count == 0.
    /// Goes straight to write lock — no double-lock overhead.
    #[inline]
    pub fn checked_purge(&self) -> usize {
        // Clear the queued flag — we're processing this entry
        self.gc_queued.store(false, Ordering::Release);

        if self.alloc_count.load(Ordering::Acquire) == 0 {
            return self.purge();
        }

        0
    }
}

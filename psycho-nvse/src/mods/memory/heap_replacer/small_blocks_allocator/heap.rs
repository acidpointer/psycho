use super::region::Region;
use super::stats::AllocatorStats;
use super::ticker::Ticker;

use libc::c_void;
use libmimalloc::heap::MiHeap;
use parking_lot::RwLock;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Region size in bytes
/// Recommended values:
/// * MIN: 128Kb
/// * MAX: 512Kb (extreme)
/// # Notes
/// * `REGION_SIZE` < `128Kb` will lead to crashes!
/// * `REGION_SIZE` > `512Kb` will lead to OOM(Out-Of-Memory)!
const REGION_SIZE: usize = 128 * 1024;

/// Region align
const REGION_ALIGN: usize = 16;

/// How many regions should be tried free backwards
/// For example, for value 3, only 3 latest regions will be tried.
const FREE_DEPTH: usize = 3;

/// Amount of ticks of inactivity to consider heap as IDLE
const HEAP_IDLE_THRESHOLD: u64 = 20;

pub struct Heap {
    /// Regions pool
    pool: RwLock<Vec<Region>>,

    /// Arced allocator stats
    stats: Arc<AllocatorStats>,

    /// Arced ticker for easy tick access
    ticker: Arc<Ticker>,

    /// Arced mi heap instance
    mi_heap: Arc<MiHeap>,

    /// Last access tick
    last_access: AtomicU64,
}

impl Heap {
    pub fn new(
        sheap_id: usize,
        mi_heap: Arc<MiHeap>,
        stats: Arc<AllocatorStats>,
        ticker: Arc<Ticker>,
    ) -> Self {
        // Initialise last_access to the current tick so that a brand-new heap
        // is never considered idle (is_idle() = false) until it has actually
        // gone unused for HEAP_IDLE_THRESHOLD ticks. Starting at 0 would make
        // every heap created after 30 ticks of uptime immediately collectible.
        let initial_tick = ticker.get_current_tick();

        Self {
            pool: RwLock::new(Vec::new()),
            mi_heap,
            stats,
            last_access: AtomicU64::new(initial_tick),
            ticker,
        }
    }

    #[inline(always)]
    fn update_last_access(&self) {
        self.last_access
            .store(self.ticker.get_current_tick(), Ordering::Relaxed);
    }

    /// Allocates memory from the region pool.
    ///
    /// Returns `None` if this heap is dead (GC-collected and pending removal),
    /// or if allocation genuinely fails (OOM).
    pub fn try_alloc(&self, size: usize, align: usize) -> Option<*mut c_void> {
        self.update_last_access();

        // Step 1. Read lock — fast path: allocate from the last (newest) region.
        {
            let pool_lock = self.pool.read();

            if let Some(last_region) = pool_lock.last()
                && let Some(ptr) = last_region.allocate(size, align)
            {
                return Some(ptr.as_ptr());
            }
        }

        // Step 2. Write lock — slow path: create a new region.
        {
            let mut pool_lock = self.pool.write();

            // Re-check: another thread may have pushed a new region while we were
            // waiting for the write lock.
            if let Some(last_region) = pool_lock.last()
                && let Some(ptr) = last_region.allocate(size, align)
            {
                return Some(ptr.as_ptr());
            }

            // For oversized allocations (size > REGION_SIZE) create a region large
            // enough to hold this specific allocation. align + 4 accounts for
            // worst-case alignment padding and the inline header.
            let region_capacity = REGION_SIZE.max(size + align + 4);

            if let Some(region) = Region::new(
                region_capacity,
                REGION_ALIGN,
                self.mi_heap.clone(),
                self.stats.clone(),
            ) && let Some(ptr) = region.allocate(size, align)
            {
                pool_lock.push(region);
                return Some(ptr.as_ptr());
            }
        }

        None
    }

    /// Try to LIFO free.
    ///
    /// `FREE_DEPTH` constant declares how many regions from the pool end
    /// will participate in attempting to perform LIFO free.
    pub fn try_free(&self, ptr: *mut c_void) -> bool {

        let pool_lock = self.pool.read();

        if !pool_lock.is_empty() {
            for (i, region) in pool_lock.iter().rev().enumerate() {
                if i >= FREE_DEPTH {
                    break;
                }

                if region.try_free(ptr) {
                    self.update_last_access();
                    return true;
                }
            }
        }

        false
    }

    /// Purge all regions. Called by game-initiated sheap resets.
    ///
    ///
    /// # Warning
    /// All allocations from this heap become invalid after this call.
    pub fn purge(&self) {
        let pool_lock = self.pool.read();

        // Purge is purge! GC will drop heap later
        for region in pool_lock.iter() {
            region.purge();
        }
    }

    #[inline]
    pub fn is_idle(&self) -> bool {
        let last_access = self.last_access.load(Ordering::Relaxed);
        let current_tick = self.ticker.get_current_tick();

        current_tick - last_access >= HEAP_IDLE_THRESHOLD
    }
}

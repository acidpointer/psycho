use super::region::Region;
use super::stats::AllocatorStats;

use libc::c_void;
use libmimalloc::heap::MiHeap;
use libpsycho::os::windows::winapi::get_current_thread_id;
use parking_lot::RwLock;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Region size in bytes
/// Recommended values:
/// * MIN: 128Kb
/// * MAX: 512Kb (extreme)
/// # Notes
/// * `REGION_SIZE` < `128Kb` will lead to crashes!
/// * `REGION_SIZE` > `512Kb` will lead to OOM(Out-Of-Memory)!
const REGION_SIZE: usize = 256 * 1024;

/// Region align
const REGION_ALIGN: usize = 16;

/// Amount of ticks of inactivity to consider heap as IDLE
const HEAP_IDLE_THRESHOLD: u64 = 100;

pub struct Heap {
    /// A/B region pools.
    /// While Pool A clears in purge(), pool B used in alloc,
    /// thus we avoid lock contention
    pools: [RwLock<Vec<Arc<Region>>>; 2],

    /// Active pool index
    active_pool_idx: AtomicUsize,

    /// Arced allocator stats
    stats: Arc<AllocatorStats>,

    /// Arced tick counter
    current_tick: Arc<AtomicU64>,

    /// Arced mi heap instance
    mi_heap: Arc<MiHeap>,

    /// Last access tick
    last_access: AtomicU64,

    /// Generation
    generation: usize,

    /// Sheap id
    sheap_id: usize,

    /// Thread id
    thread_id: u32,

    /// Allocations counter for this heap
    alloc_count: AtomicUsize,
}

impl Heap {
    pub fn new(
        sheap_id: usize,
        generation: usize,
        mi_heap: Arc<MiHeap>,
        stats: Arc<AllocatorStats>,
        current_tick: Arc<AtomicU64>,
    ) -> Self {
        // Initialise last_access to the current tick so that a brand-new heap
        // is never considered idle (is_idle() = false) until it has actually
        // gone unused for HEAP_IDLE_THRESHOLD ticks. Starting at 0 would make
        // every heap created after 30 ticks of uptime immediately collectible.
        let initial_tick = current_tick.load(Ordering::Acquire);

        let thread_id = get_current_thread_id();

        Self {
            generation,
            sheap_id,
            active_pool_idx: AtomicUsize::new(0),
            pools: [RwLock::new(Vec::new()), RwLock::new(Vec::new())],
            mi_heap,
            stats,
            last_access: AtomicU64::new(initial_tick),
            current_tick,
            thread_id,
            alloc_count: AtomicUsize::new(0),
        }
    }

    #[inline(always)]
    pub fn get_thread_id(&self) -> u32 {
        self.thread_id
    }

    #[inline(always)]
    pub fn get_sheap_id(&self) -> usize {
        self.sheap_id
    }

    #[inline(always)]
    pub fn get_generation(&self) -> usize {
        self.generation
    }

    #[inline(always)]
    fn update_last_access(&self) {
        let current_tick = self.current_tick.load(Ordering::Acquire);

        self.last_access
            .store(current_tick, Ordering::Relaxed);
    }

    /// Allocates memory from the region pool.
    ///
    /// Returns `None` if this heap is dead (GC-collected and pending removal),
    /// or if allocation genuinely fails (OOM).
    #[inline]
    pub fn try_alloc(&self, size: usize, align: usize) -> Option<*mut c_void> {
        self.update_last_access();

        let pool_idx = self.active_pool_idx.load(Ordering::Acquire);
        let pool = &self.pools[pool_idx];

        // Step 1. Read lock — fast path: allocate from the last (newest) region.
        {
            let pool_lock = pool.read();

            if let Some(last_region) = pool_lock.last()
                && let Some(ptr) = last_region.allocate(size, align)
            {
                self.alloc_count.fetch_add(1, Ordering::Release);
                return Some(ptr.as_ptr());
            }
        }

        // Step 2. Write lock — slow path: create a new region.
        {
            let mut pool_lock = pool.write();

            // Re-check: another thread may have pushed a new region while we were
            // waiting for the write lock.
            if let Some(last_region) = pool_lock.last()
                && let Some(ptr) = last_region.allocate(size, align)
            {
                self.alloc_count.fetch_add(1, Ordering::Release);
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
                pool_lock.push(Arc::new(region));
                self.alloc_count.fetch_add(1, Ordering::Release);
                return Some(ptr.as_ptr());
            }
        }

        None
    }

    #[inline]
    pub fn free(&self, _ptr: *mut c_void) {
        self.alloc_count.fetch_sub(1, Ordering::Release);
    }

    /// Purge all regions. Called by game-initiated sheap resets.
    ///
    ///
    /// # Warning
    /// All allocations from this heap become invalid after this call.
    /// # Returns
    /// Amount of purged regions
    #[inline]
    pub fn purge(&self) -> usize {
        let old_idx = self.active_pool_idx.load(Ordering::Acquire);

        // Update active pool index, so alloc is not blocked
        let new_idx = 1 - old_idx;
        self.active_pool_idx.store(new_idx, Ordering::Release);

        let mut pool_lock = self.pools[old_idx].write();

        let old_len = pool_lock.len();

        if !pool_lock.is_empty() {
            pool_lock.clear();
        }

        self.update_last_access();

        old_len
    }

    /// Returns len of (active) pool
    /// 
    /// Even if we have A/B pool logic implemented,
    /// valid len is only for active pool.
    #[inline]
    pub fn get_pool_len(&self) -> usize {
        let active_idx = self.active_pool_idx.load(Ordering::Acquire);
        let active_pool = self.pools[active_idx].read();

        active_pool.len()
    }

    /// Checked purge
    /// 
    /// Calls for regular `purge` if:
    /// * `alloc_count == 0` 
    /// * `selg.get_pool_len() > 0`
    /// 
    /// Used by garbage collector.
    #[inline]
    pub fn checked_purge(&self) -> usize {
        let alloc_count = self.alloc_count.load(Ordering::Acquire);

        let curr_pool_len = self.get_pool_len();

        if curr_pool_len == 0 {
            return 0;
        }

        if alloc_count == 0 && curr_pool_len > 0 {
            return self.purge();
        }

        0
    }

    #[inline]
    pub fn is_idle(&self) -> bool {
        let last_access = self.last_access.load(Ordering::Relaxed);
        let current_tick = self.current_tick.load(Ordering::Acquire);

        current_tick - last_access >= HEAP_IDLE_THRESHOLD
    }
}

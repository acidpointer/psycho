//! RegionAllocator
//! This is memory allocator designed for scrap heap of Fallout: New Vegas game.
//! It aims to be high performance and it have deffered purge and automatic memory
//! clean-up through detection of IDLE regions and dropping them.

use clashmap::ClashMap;
use crossfire::flavor::{self, Queue};
use libc::c_void;
use libmimalloc::heap::MiHeap;
use libpsycho::common::align_up;
use parking_lot::RwLock;
use std::{
    cell::RefCell,
    collections::BTreeMap,
    ptr::NonNull,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

// ==========================================================================================

/// Size of each allocation region in bytes
///
/// Recommended minimum: 128Kb
/// Recommended maximum: 512Kb
///
/// Everything that less 128Kb will lead to crash
const REGION_SIZE: usize = 256 * 1024;

/// How many regions to pre-allocate
const MIN_REGIONS: usize = 16;

/// Alignment guarantee for all allocations
const REGION_ALIGN: usize = 16;

/// Shift amount to convert addresses to page numbers (4096-byte pages)
const PAGE_SHIFT: usize = 12;

/// Total amount of shards
const SHARDS_AMOUNT: usize = 16;

/// Delay between ticks
const TICK_DURATION: Duration = Duration::from_millis(500);

/// Delay between gc cycles
const GC_DURATION: Duration = Duration::from_millis(500);

/// Generational GC: Young generation idle threshold (aggressive)
/// Young regions = short-lived (projectiles, particles, sounds)
/// 30 ticks × 500ms = 15 seconds idle before recycling
const YOUNG_GEN_IDLE_TICKS: u64 = 30;

/// Generational GC: Old generation idle threshold (relaxed)
/// Old regions = long-lived (game state, level data)
/// 200 ticks × 500ms = 100 seconds idle before recycling
const OLD_GEN_IDLE_TICKS: u64 = 200;

/// Generational GC: Promotion threshold
/// Region survives this many GC cycles → promoted to old generation
const OLD_GEN_THRESHOLD: usize = 3;

// GUARDS:

const _: () = assert!(
    SHARDS_AMOUNT > 0,
    "SHARDS_AMOUNT must be greater than zero!"
);
const _: () = assert!(
    SHARDS_AMOUNT.is_power_of_two(),
    "Performance Warning: SHARDS_AMOUNT should be a power of two!"
);

// ==========================================================================================

/// Static instance of MiHeap (mimalloc heap)
static MI_HEAP: LazyLock<MiHeap> = LazyLock::new(MiHeap::new);

// ==========================================================================================

/// Fast Send + Sync non-blocking hashmap with ahash hasher
type HashMapSync<K, V> = ClashMap<K, V, ahash::RandomState>;

/// BTree-based region pool for O(log n) lookups
///
/// This design achieves:
/// - O(log n) free() via BTreeMap range query to find region owner
/// - O(1) amortized alloc_align() via available_regions Vec
struct PoolData {
    /// ALL regions sorted by start_page address
    /// Key: start_page (region start address >> PAGE_SHIFT)
    /// Used for O(log n) lookup during free()
    regions_by_addr: BTreeMap<usize, Region>,

    /// Start pages of regions with available space
    /// Used for O(1) allocation attempts
    /// Maintained by removing exhausted regions and adding new/reset regions
    available_regions: Vec<usize>,
}

impl PoolData {
    fn new() -> Self {
        Self {
            regions_by_addr: BTreeMap::new(),
            available_regions: Vec::new(),
        }
    }

    /// Clean up exhausted regions from available list
    fn clean_exhausted_regions(&mut self) {
        // Remove exhausted regions from available_regions
        self.available_regions.retain(|&start_page| {
            if let Some(region) = self.regions_by_addr.get(&start_page) {
                // Check if region has space by attempting a small allocation
                let current_offset = region.offset.load(Ordering::Acquire);
                current_offset < region.capacity
            } else {
                false
            }
        });
    }
}

/// Single region pool per sheap - simplified design with optimizations
/// Read locks: multiple threads allocate concurrently
/// Write locks: only GC (brief, removes idle regions)
type RegionPool = Arc<RwLock<PoolData>>;

/// Computes which shard should handle a given heap key.
///
/// Uses Fibonacci Hashing to ensure uniform distribution across shards,
/// even when keys are closely clustered (like aligned pointers).
#[inline(always)]
fn get_shard_idx(key: usize) -> usize {
    // 1. Select the Golden Ratio constant based on architecture width
    // 32-bit: (2^32 / phi) = 0x9E3779B9
    // 64-bit: (2^64 / phi) = 0x9E3779B97F4A7C15
    #[cfg(target_pointer_width = "64")]
    const PHI: usize = 0x9e3779b97f4a7c15;

    #[cfg(target_pointer_width = "32")]
    const PHI: usize = 0x9e3779b9;

    // 2. Multiply to spread entropy across the entire word
    let hash = key.wrapping_mul(PHI);

    // 3. Shift and Modulo
    // We use the high bits of the hash as they have the highest entropy
    // after the multiplication.
    // If SHARDS_AMOUNT is a power of 2, the compiler optimizes this to a bit-mask.
    let high_bits = hash >> (usize::BITS as usize / 2);

    high_bits % SHARDS_AMOUNT
}

struct Region {
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

    /// SheapId used for identifying of this region
    /// Value 0 means that region is clear and not belongs to any heap
    sheap_id: AtomicUsize,

    /// On which tick this region was last used for allocation
    /// Value 0 means that region is clear and not belongs to any heap
    last_access: AtomicU64,

    /// Generation for generational GC
    /// 0 = young generation (scanned frequently)
    /// Increments each time region survives GC, caps at OLD_GEN_THRESHOLD
    generation: AtomicUsize,

    stats: Arc<AllocatorStats>,
}

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
    fn new(capacity: usize, align: usize, stats: Arc<AllocatorStats>) -> Option<Self> {
        let ptr = MI_HEAP.malloc_aligned(capacity, align);
        let start = NonNull::new(ptr as *mut u8)?;

        stats.add_total_alloc_mem(capacity as u64);

        let start_ptr = start.as_ptr() as usize;

        Some(Self {
            start,
            capacity,
            sheap_id: AtomicUsize::new(0),
            last_access: AtomicU64::new(0),
            offset: AtomicUsize::new(0),
            start_page: start_ptr >> PAGE_SHIFT,
            end_page: (start_ptr + capacity) >> PAGE_SHIFT,
            generation: AtomicUsize::new(0), // Start as young generation
            stats,
        })
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
    fn allocate(&self, size: usize, align: usize) -> Option<NonNull<c_void>> {
        let start_addr = self.start.as_ptr() as usize;
        let mut current_offset = self.offset.load(Ordering::Acquire);

        loop {
            // 1. Calculate the earliest possible data address
            // We must leave at least 4 bytes for the header.
            let min_data_addr = start_addr + current_offset + 4;

            // 2. Align the data pointer to the requested alignment
            let data_addr = align_up(min_data_addr, align);

            // 3. The header is NOW guaranteed to be exactly 4 bytes before data
            let header_addr = data_addr - 4;

            let requested_end = (data_addr - start_addr) + size;

            if requested_end > self.capacity {
                return None;
            }

            match self.offset.compare_exchange_weak(
                current_offset,
                requested_end, // New offset is the end of the data
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    unsafe {
                        let size_ptr = header_addr as *mut AtomicU32;
                        (*size_ptr).store(size as u32, Ordering::Release);
                    }
                    return NonNull::new(data_addr as *mut c_void);
                }
                Err(next_val) => current_offset = next_val,
            }
        }
    }

    /// Attempts to undo the last allocation if the pointer matches.
    #[inline]
    fn try_free(&self, ptr: *mut c_void) -> bool {
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

    /// Returns true if pointer belongs to this region
    #[allow(dead_code)]
    pub fn is_our_ptr(&self, ptr: *mut c_void) -> bool {
        let addr = ptr as usize;
        let page = addr >> PAGE_SHIFT;

        (self.start_page <= page) && (page < self.end_page)
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        self.stats.sub_total_alloc_mem(self.capacity as u64);

        unsafe {
            libmimalloc::mi_free(self.start.as_ptr() as *mut c_void);
        }
    }
}

#[derive(Default)]
pub struct AllocatorStats {
    /// Total allocated memory for all regions
    total_allocated_mem: AtomicU64,
}

impl AllocatorStats {
    #[inline]
    fn add_total_alloc_mem(&self, size: u64) -> u64 {
        self.total_allocated_mem.fetch_add(size, Ordering::Relaxed)
    }

    #[inline]
    fn sub_total_alloc_mem(&self, size: u64) -> u64 {
        self.total_allocated_mem.fetch_sub(size, Ordering::Relaxed)
    }

    #[inline]
    fn get_total_alloc_mem(&self) -> u64 {
        self.total_allocated_mem.load(Ordering::Acquire)
    }
}

// ==========================================================================================
// TLS CACHE
// ==========================================================================================

/// Thread-local cache for fast repeated allocations
///
/// Simple single-entry cache - most game threads use only one heap repeatedly.
/// Generation counter ensures cache is invalidated on purge events.
struct TlsCache {
    sheap_id: usize,
    pool: Option<RegionPool>,
    generation: u64,
}

impl TlsCache {
    fn new() -> Self {
        Self {
            sheap_id: 0,
            pool: None,
            generation: 0,
        }
    }

    /// Check if cache contains entry and return the cached region pool
    #[inline(always)]
    fn get(&self, sheap_id: usize, global_generation: u64) -> Option<RegionPool> {
        // Generation mismatch - cache is stale
        if self.generation != global_generation {
            return None;
        }

        // Check if cached sheap_id matches
        if self.sheap_id == sheap_id {
            self.pool.clone()
        } else {
            None
        }
    }

    /// Update cache entry
    #[inline(always)]
    fn set(&mut self, sheap_id: usize, pool: RegionPool, generation: u64) {
        self.sheap_id = sheap_id;
        self.pool = Some(pool);
        self.generation = generation;
    }

    /// Invalidate cache entry
    #[allow(dead_code)]
    #[inline(always)]
    fn invalidate(&mut self) {
        self.pool = None;
    }
}

thread_local! {
    static TLS_CACHE: RefCell<TlsCache> = RefCell::new(TlsCache::new());
}

// ==========================================================================================

pub struct RegionAllocator {
    empty_regions: flavor::List<Region>,

    /// Current tick
    tick: AtomicU64,

    /// Global generation counter - incremented on purge/invalidation events
    /// Used to invalidate TLS caches across all threads
    generation: AtomicU64,

    run_ticker: AtomicBool,
    run_gc: AtomicBool,

    stats: Arc<AllocatorStats>,

    /// Shards now store Arc<RwLock<Vec<Region>>> for safe sharing and TLS caching
    shards: [HashMapSync<usize, RegionPool>; SHARDS_AMOUNT],
}

// Safety: RegionAllocator is non-blocking and thread safe by design
unsafe impl Send for RegionAllocator {}

// Safety: RegionAllocator is non-blocking and thread safe by design
unsafe impl Sync for RegionAllocator {}

impl RegionAllocator {
    /// Create new RegionAllocator instance, returns
    ///
    /// Initialize regions and start worker threads
    pub fn new() -> Arc<Self> {
        let instance = Self {
            empty_regions: flavor::List::new(),
            tick: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            run_ticker: AtomicBool::new(true),
            run_gc: AtomicBool::new(true),
            stats: Arc::new(AllocatorStats::default()),
            shards: Default::default(),
        };

        let regions: Vec<Region> = (0..MIN_REGIONS)
            .filter_map(|_| Region::new(REGION_SIZE, REGION_ALIGN, instance.stats.clone()))
            .collect();

        for region in regions {
            match instance.empty_regions.push(region) {
                Ok(_) => {}
                Err(_err) => {
                    log::error!("RegionAllocator: Failed to push region to empty queue!");
                }
            }
        }

        let instance_arc = Arc::new(instance);

        // Ticker thread
        let instance1 = instance_arc.clone();
        thread::spawn(move || {
            let instance = instance1.clone();
            loop {
                let is_run = instance.run_ticker.load(Ordering::Acquire);

                if !is_run {
                    break;
                }

                // increment tick counter
                let current_tick = instance.tick.fetch_add(1, Ordering::Relaxed);

                if current_tick.is_multiple_of(4) {
                    let total_mem = instance.stats.get_total_alloc_mem();
                    log::info!(
                        "RegionAllocator: [STATS] Total allocated: {} MB ({} bytes)",
                        total_mem / 1024 / 1024,
                        total_mem
                    );
                }

                thread::sleep(TICK_DURATION);
            }
        });

        // Parallel generational GC: one thread per shard
        for shard_index in 0..SHARDS_AMOUNT {
            let instance2 = instance_arc.clone();
            thread::spawn(move || {
                let instance = instance2;

                log::info!(
                    "RegionAllocator: Generational GC thread for SHARD#{} initialized!",
                    shard_index
                );

                loop {
                    let is_run = instance.run_gc.load(Ordering::Acquire);

                    if !is_run {
                        return;
                    }

                    instance.gc_shard(shard_index);
                    thread::sleep(GC_DURATION);
                }
            });
        }

        instance_arc.clone()
    }

    /// Get or create region pool with TLS caching
    ///
    /// This is the HOT PATH optimization - we cache the Arc<RwLock<Vec<Region>>>
    /// to completely skip HashMap lookups on repeated allocations!
    #[inline(always)]
    fn get_or_create_pool(&self, sheap_id: usize) -> RegionPool {
        let generation = self.generation.load(Ordering::Acquire);
        let shard_idx = get_shard_idx(sheap_id);
        let shard = &self.shards[shard_idx];

        // Try TLS cache first (HOT PATH)
        if let Some(cached_pool) = TLS_CACHE.with(|cache| cache.borrow().get(sheap_id, generation))
        {
            // Verify cached pool is still valid in HashMap
            // If purged, HashMap won't have it - cached Arc is stale!
            if shard.contains_key(&sheap_id) {
                return cached_pool;
            }
            // Cache hit but pool was purged - fall through to HashMap lookup
        }

        // Cache miss or stale - look up in HashMap (COLD PATH)
        let pool = if let Some(existing) = shard.get(&sheap_id) {
            existing.clone()
        } else {
            let new_pool = Arc::new(RwLock::new(PoolData::new()));
            let _ = shard.insert(sheap_id, new_pool.clone());
            new_pool
        };

        // Update TLS cache for next time
        TLS_CACHE.with(|cache| {
            cache.borrow_mut().set(sheap_id, pool.clone(), generation);
        });

        pool
    }

    /// Parallel generational garbage collector for a single shard
    ///
    /// Uses generational GC strategy:
    /// - Young generation (gen 0-2): Aggressive collection - short-lived allocations
    /// - Old generation (gen 3+): Relaxed collection - long-lived allocations
    ///
    /// Each shard has its own GC thread running in parallel.
    fn gc_shard(&self, shard_index: usize) {
        let tick = self.tick.load(Ordering::Acquire);
        let shard = &self.shards[shard_index];

        // Early exit if shard is empty (avoid iterating empty shards)
        if shard.is_empty() {
            return;
        }

        // Process ALL pools in this shard (parallel GC!)
        shard.iter().for_each(|entry| {
            let sheap_id = entry.key();
            let pool = entry.value();

            // PHASE 1: Scan regions under READ lock (concurrent with allocations!)
            let (regions_to_remove, old_len) = {
                let pool_data = pool.read();
                let old_len = pool_data.regions_by_addr.len();

                // Early exit if pool is empty
                if old_len == 0 {
                    return;
                }

                // Generational GC: separate young and old regions
                let regions_to_remove: Vec<usize> = pool_data
                    .regions_by_addr
                    .iter()
                    .filter_map(|(address, region)| {
                        let generation = region.generation.load(Ordering::Acquire);
                        let last_tick = region.last_access.load(Ordering::Acquire);
                        let idle_ticks = tick.saturating_sub(last_tick);

                        // Young generation: aggressive collection (short-lived allocations)
                        if generation < OLD_GEN_THRESHOLD {
                            if idle_ticks > YOUNG_GEN_IDLE_TICKS {
                                // Idle young region → recycle it
                                return Some(*address);
                            } else if idle_ticks > 0 {
                                // Active young region → promote it
                                region.generation.store(generation + 1, Ordering::Release);
                            }
                        }
                        // Old generation: relaxed collection (long-lived allocations)
                        else if idle_ticks > OLD_GEN_IDLE_TICKS {
                            // Idle old region → recycle it
                            return Some(*address);
                        }

                        None
                    })
                    .collect();

                (regions_to_remove, old_len)
            }; // READ lock released here!

            // Early exit if nothing to recycle
            if regions_to_remove.is_empty() {
                return;
            }

            // PHASE 2: Remove regions under WRITE lock (brief, only for removal!)
            let new_len = {
                let mut pool_data = pool.write();

                for address in &regions_to_remove {
                    if let Some(region) = pool_data.regions_by_addr.remove(address) {
                        // Reset region state back to young generation
                        region.offset.store(0, Ordering::Release);
                        region.sheap_id.store(0, Ordering::Release);
                        region.last_access.store(0, Ordering::Release);
                        region.generation.store(0, Ordering::Release);

                        // Push back to empty_regions for reuse
                        let _ = self.empty_regions.push(region);
                    }
                }

                // Clean up available_regions list - remove recycled regions
                pool_data
                    .available_regions
                    .retain(|start_page| !regions_to_remove.contains(start_page));

                pool_data.regions_by_addr.len()
            }; // WRITE lock released here!

            let recycled = old_len - new_len;

            if recycled > 0 {
                log::info!(
                    "RegionAllocator: [GC SHARD#{}] recycled {} regions from sheap_id={:X}",
                    shard_index,
                    recycled,
                    sheap_id
                );
            }
        });
    }

    #[inline(always)]
    pub fn alloc_align(&self, sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
        let sheap_id = sheap_ptr as usize;

        // Protection from stupid pointers
        if sheap_id < 0x10000 {
            return std::ptr::null_mut();
        }

        // Debug assertions - catch bugs early in development
        debug_assert!(size > 0, "RegionAllocator: zero-size allocation");
        debug_assert!(size <= REGION_SIZE, "RegionAllocator: allocation too large for region (size={}, max={})", size, REGION_SIZE);
        debug_assert!(align.is_power_of_two(), "RegionAllocator: alignment must be power of two (align={})", align);
        debug_assert!(align <= REGION_ALIGN, "RegionAllocator: alignment too large for region (align={}, max={})", align, REGION_ALIGN);

        // Relaxed ordering: tick only needs eventual consistency (performance optimization)
        let tick = self.tick.load(Ordering::Relaxed);

        // Get cached region pool (skips HashMap lookup on cache hit!)
        let pool = self.get_or_create_pool(sheap_id);

        // Step 1. Try to get empty region first (pre-warmed regions)
        if let Some(region) = self.empty_regions.pop() {
            // Allocate on this region
            if let Some(ptr) = region.allocate(size, align) {
                // Update sheap_id for selected region
                region.sheap_id.store(sheap_id, Ordering::Release);
                region.last_access.store(tick, Ordering::Release);

                let start_page = region.start_page;

                // Add to pool - use write lock
                let mut pool_data = pool.write();
                pool_data.regions_by_addr.insert(start_page, region);
                pool_data.available_regions.push(start_page);

                return ptr.as_ptr();
            }

            // On failed allocation, we return region back to empty queue
            if let Err(_failed_region) = self.empty_regions.push(region) {
                log::error!(
                    "RegionAllocator: Failed to push region back to empty queue after failed allocation!"
                );
            }
        }

        // Step 2. Try to allocate from existing available regions
        // Use read lock for fast concurrent path
        {
            let pool_data = pool.read();

            // LIFO optimization: try NEWEST regions first (most likely to have space)
            // Reversed iteration = O(1) hot path instead of O(n) scan!
            for &start_page in pool_data.available_regions.iter().rev() {
                if let Some(region) = pool_data.regions_by_addr.get(&start_page)
                    && let Some(ptr) = region.allocate(size, align)
                {
                    region.last_access.store(tick, Ordering::Release);
                    return ptr.as_ptr();
                }
                // Region is now full - GC will clean it up, no write lock needed!
            }
        }

        // Step 3. Allocate new region as last resort
        if let Some(region) = Region::new(REGION_SIZE, REGION_ALIGN, self.stats.clone())
            && let Some(ptr) = region.allocate(size, align)
        {
            region.last_access.store(tick, Ordering::Release);
            region.sheap_id.store(sheap_id, Ordering::Release);

            let start_page = region.start_page;

            // Add to pool
            let mut pool_data = pool.write();
            pool_data.regions_by_addr.insert(start_page, region);
            pool_data.available_regions.push(start_page);

            return ptr.as_ptr();
        }

        // Step 4. Failed - return null
        // If we can't allocate, we can't. This means GC or memory management is fucked.
        log::error!(
            "RegionAllocator: alloc_align() failed! sheap_ptr={:p}, size={}, align={}",
            sheap_ptr,
            size,
            align
        );
        std::ptr::null_mut()
    }

    /// Purge all regions which belongs to provided sheap_ptr
    ///
    /// Remove from HashMap + invalidate TLS caches to allow GC to recycle.
    #[inline(always)]
    pub fn purge(&self, sheap_ptr: *mut c_void) {
        let sheap_id = sheap_ptr as usize;
        let shard_idx = get_shard_idx(sheap_id);
        let shard = &self.shards[shard_idx];

        // Step 1: Remove from HashMap IMMEDIATELY to prevent further allocations
        shard.remove(&sheap_id);

        // Step 2: Increment generation to invalidate ALL TLS caches
        // This is CRITICAL - without this, TLS caches hold Arc references preventing GC!
        self.generation.fetch_add(1, Ordering::Release);

        // Regions will be cleaned up by GC when Arc refcount drops to 0
    }

    /// Attempt to free memory
    ///
    /// Tries to do LIFO free, otherwise NOOP.
    /// Uses BTreeMap range query for O(log n) region lookup.
    #[inline(always)]
    pub fn free(&self, sheap_ptr: *mut c_void, ptr: *mut c_void) -> bool {
        let sheap_id = sheap_ptr as usize;
        let shard_idx = get_shard_idx(sheap_id);
        let shard = &self.shards[shard_idx];

        if let Some(pool) = shard.get(&sheap_id) {
            let pool_data = pool.read();
            let page = (ptr as usize) >> PAGE_SHIFT;

            // Use BTreeMap range query to find the region containing this pointer
            // Find the largest start_page that is <= our page
            // This is O(log n) binary search!
            if let Some((&_start_page, region)) =
                pool_data.regions_by_addr.range(..=page).next_back()
            {
                // Verify the pointer is actually in this region's range
                if region.is_our_ptr(ptr) {
                    return region.try_free(ptr);
                }
            }
        }

        false
    }
}

impl Drop for RegionAllocator {
    fn drop(&mut self) {
        // stop all threads by changing run flag for each
        self.run_ticker.store(false, Ordering::Release);
        self.run_gc.store(false, Ordering::Release);
    }
}

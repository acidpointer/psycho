//! # High-Performance Epoch-Based Region Allocator (ScrapHeap)
//!
//! ## Overview
//! A specialized allocator for short-lived, high-frequency allocations in the Fallout: New Vegas engine.
//! Designed to prevent fragmentation and mutex contention in the original 32-bit Gamebryo engine.
//!
//! ## Key Features
//! 1. **Region-Based Allocation**: Large 256KB regions for O(1) pointer-bump allocations
//! 2. **Epoch-Based Purging**: Memory reclaimed at cycle boundaries (e.g., end of frame)
//! 3. **Sharded Registry**: 16 shards prevent global lock contention in multi-threaded environments
//! 4. **Thread-Local Caching**: Hot-path optimization bypassing sharding for repeated calls
//! 5. **Memory Reclamation**: Active monitoring returns unused memory to mimalloc

use ahash::AHashMap;
use libc::c_void;
use libmimalloc::heap::MiHeap;
use log::{debug, error};
use parking_lot::Mutex;
use std::cell::RefCell;
use std::ptr::NonNull;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Size of each allocation region in bytes (128KB)
const REGION_SIZE: usize = 128 * 1024;

/// Minimum alignment guarantee for all allocations
const MIN_ALIGN: usize = 16;

/// Number of empty cycles before a region is considered for purging
const EMPTY_THRESHOLD: usize = 2; // 5

/// Number of shards for distributing heap registry access
const MAX_SHARDS: usize = 16;

/// Shift amount to convert addresses to page numbers (4096-byte pages)
const PAGE_SHIFT: usize = 12;

/// Global memory limit before aggressive purging (512 MiB)
const GLOBAL_MEMORY_LIMIT: usize = 512 * 1024 * 1024;

// ============================================================================
// GLOBAL STATE
// ============================================================================

/// Global mimalloc heap instance for backing memory allocations
static MI_HEAP: LazyLock<MiHeap> = LazyLock::new(MiHeap::new);

/// Global tick counter for tracking heap access recency
static GLOBAL_TICK: AtomicU64 = AtomicU64::new(0);

/// Tracks total memory allocated across all regions
static TOTAL_ALLOCATED_MEM: AtomicUsize = AtomicUsize::new(0);

/// Counter incremented on heap eviction; invalidates TLS caches
static GLOBAL_EVICTION_COUNT: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// CORE DATA STRUCTURES
// ============================================================================

/// A contiguous memory block used for bump-pointer allocation.
///
/// Regions are allocated from mimalloc and provide O(1) allocation
/// by simply bumping an offset pointer. When a region becomes full,
/// a new region is allocated.
struct Region {
    /// Start address of the allocated memory block
    start: NonNull<u8>,

    /// Total capacity of the region in bytes
    capacity: usize,

    /// Current allocation offset within the region
    offset: usize,

    /// Number of consecutive purge cycles where the region was empty
    empty_cycles: AtomicUsize,

    start_page: usize,
    end_page: usize,
}

impl Region {
    /// Creates a new memory region backed by mimalloc.
    ///
    /// # Arguments
    /// * `capacity` - Size of the region to allocate
    /// * `align` - Required alignment for the region
    ///
    /// # Returns
    /// `Some(Region)` if allocation succeeded, `None` otherwise
    fn new(capacity: usize, align: usize) -> Option<Self> {
        let ptr = MI_HEAP.malloc_aligned(capacity, align);
        let start = NonNull::new(ptr as *mut u8)?;

        let total = TOTAL_ALLOCATED_MEM.fetch_add(capacity, Ordering::Relaxed) + capacity;

        debug!(
            "Region::new: Allocated {} KB (Global: {} MB)",
            capacity / 1024,
            total / (1024 * 1024)
        );

        let start_ptr = start.as_ptr() as usize;

        Some(Self {
            start,
            capacity,
            offset: 0,
            empty_cycles: AtomicUsize::new(0),
            start_page: start_ptr >> PAGE_SHIFT,
            end_page: (start_ptr + capacity - 1) >> PAGE_SHIFT,
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
    fn allocate(&mut self, size: usize, align: usize) -> Option<NonNull<u8>> {
        let current_addr = self.start.as_ptr() as usize + self.offset;
        let aligned_addr = align_up(current_addr, align);
        let new_offset = (aligned_addr - self.start.as_ptr() as usize) + size;

        if new_offset > self.capacity {
            return None;
        }

        self.offset = new_offset;
        self.empty_cycles.store(0, Ordering::Release);

        NonNull::new(aligned_addr as *mut u8)
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        TOTAL_ALLOCATED_MEM.fetch_sub(self.capacity, Ordering::Relaxed);

        unsafe {
            libmimalloc::mi_free(self.start.as_ptr() as *mut c_void);
        }
    }
}

/// A collection of Regions representing a single game-engine ScrapHeap instance.
///
/// Each ScrapHeap manages multiple regions and provides allocation services
/// for a specific allocation context (e.g., a script execution block).
pub struct ScrapHeap {
    /// List of regions owned by this heap
    regions: Vec<Region>,
    
    /// Vec from page number to region index for fast pointer lookup
    page_to_region: Vec<(usize, usize)>,

    /// Index of the currently active region (most likely to have free space)
    active_index: usize,
    
    /// Last global tick when this heap was accessed
    last_access: u64,
}

impl ScrapHeap {
    /// Creates a new empty ScrapHeap.
    pub fn new() -> Self {
        Self {
            regions: Vec::with_capacity(8),
            page_to_region: Vec::with_capacity(4),
            active_index: 0,
            last_access: 0,
        }
    }

    /// Primary allocation entry point for this heap.
    ///
    /// # Arguments
    /// * `size` - Size of the allocation in bytes
    /// * `align` - Required alignment for the allocation
    ///
    /// # Returns
    /// Pointer to allocated memory, or null pointer if allocation failed
    pub fn alloc_aligned(&mut self, size: usize, align: usize) -> *mut c_void {
        if size == 0 {
            return std::ptr::null_mut();
        }
        let align = align.max(MIN_ALIGN);

        // Try current active index
        if let Some(region) = self.regions.get_mut(self.active_index)
            && let Some(ptr) = region.allocate(size, align)
        {
            return ptr.as_ptr() as *mut c_void;
        }

        // Optimization: Only search forward from the active index
        // to avoid re-checking guaranteed-full regions.
        for i in (self.active_index + 1)..self.regions.len() {
            if let Some(ptr) = self.regions[i].allocate(size, align) {
                self.active_index = i;
                return ptr.as_ptr() as *mut c_void;
            }
        }

        self.expand_and_allocate(size, align)
    }

    /// Expands the heap by allocating a new region and performs allocation within it.
    ///
    /// Optimized to maintain the sorted page-to-region map with minimal overhead.
    /// # Arguments
    /// * `size` - Size of the allocation in bytes
    /// * `align` - Required alignment for the allocation
    ///
    /// # Returns
    /// Pointer to allocated memory, or falls back to global allocator on failure
    fn expand_and_allocate(&mut self, size: usize, align: usize) -> *mut c_void {
        let capacity = calculate_required_capacity(size, align);

        // Attempt to allocate from the backing mimalloc heap
        if let Some(mut region) = Region::new(capacity, align) {
            // This must succeed because the region was just created with sufficient capacity
            let ptr = region
                .allocate(size, align)
                .expect("Critical: Allocation failed in a fresh region");

            let new_idx = self.regions.len();
            let new_entry = (region.start_page, new_idx);

            // --- Optimized Map Update ---
            // In most scenarios, new regions are mapped at higher addresses.
            // We check if we can simply push to avoid a full O(N log N) sort.
            if self.page_to_region.is_empty()
                || new_entry.0 >= self.page_to_region.last().unwrap().0
            {
                self.page_to_region.push(new_entry);
            } else {
                self.page_to_region.push(new_entry);
                self.page_to_region.sort_unstable_by_key(|k| k.0);
            }

            self.regions.push(region);
            self.active_index = new_idx;

            return ptr.as_ptr() as *mut c_void;
        }

        // --- Critical Fallback ---
        error!(
            "ScrapHeap: Critical allocation failure for {} bytes! Falling back to global heap.",
            size
        );

        // If the region system fails (e.g., address space exhaustion),
        // we fall back to a standard aligned allocation to prevent a crash.
        MI_HEAP.malloc_aligned(size, align)
    }

    /// Resets all allocation offsets and prunes unused regions.
    ///
    /// Called at epoch boundaries (e.g., end of frame) to reclaim memory
    /// while keeping region allocations for future use.
    pub fn purge(&mut self) {
        let old_region_count = self.regions.len();

        // Update region state and track empty cycles
        for region in &mut self.regions {
            let current_empty = region.empty_cycles.load(Ordering::Relaxed);

            if region.offset == 0 {
                region.empty_cycles.fetch_add(1, Ordering::Relaxed);
            } else {
                region.offset = 0;
                // If the engine called free() many times, we keep the empty_cycles high
                if current_empty < 10 {
                    region.empty_cycles.store(0, Ordering::Relaxed);
                }
            }
        }

        // Remove regions that have been empty for too many cycles
        let purge_threshold = get_purge_threshold();
        self.regions
            .retain(|r| r.empty_cycles.load(Ordering::Acquire) < purge_threshold);

        // Rebuild region map if regions were removed
        if self.regions.len() != old_region_count {
            self.rebuild_region_map();
            self.conditionally_shrink();
        }

        // Reset to first region for next allocation cycle
        self.active_index = 0;
    }

    /// Rebuilds the page-to-region map from scratch.
    ///
    /// Ensures the map accurately reflects current regions after purging.
    fn rebuild_region_map(&mut self) {
        // Completely clear and rebuild to ensure indices match the new Vec positions
        self.page_to_region.clear();
        for (idx, region) in self.regions.iter().enumerate() {
            self.page_to_region.push((region.start_page, idx));
        }
        // Re-sort because the order might have been preserved, but it's safer to ensure
        self.page_to_region.sort_unstable_by_key(|k| k.0);
    }

    /// Shrinks internal containers if they're significantly oversized.
    ///
    /// Prevents holding onto excessive capacity after large purges.
    fn conditionally_shrink(&mut self) {
        if self.regions.capacity() > self.regions.len() * 2 {
            self.regions.shrink_to_fit();
            self.page_to_region.shrink_to_fit();
            //self.region_map.shrink_to_fit();
        }
    }

    #[inline]
    pub fn get_region_index_for_addr(&self, addr: usize) -> Option<usize> {
        let page = addr >> PAGE_SHIFT;

        // Find the first region that starts AT OR AFTER this page
        let idx = self.page_to_region.binary_search_by_key(&page, |&(p, _)| p);

        match idx {
            Ok(found_idx) => Some(self.page_to_region[found_idx].1),
            Err(insert_idx) => {
                // If not found exactly, it might be inside the previous region in the sorted list
                if insert_idx > 0 {
                    let (_, region_idx) = self.page_to_region[insert_idx - 1];
                    let region = &self.regions[region_idx];
                    // Verify the page actually falls within this region's bounds
                    if page <= region.end_page {
                        return Some(region_idx);
                    }
                }
                None
            }
        }
    }
}

// ============================================================================
// SHARDING INFRASTRUCTURE
// ============================================================================

/// A shard containing a subset of heap registrations.
///
/// Each shard has its own mutex, allowing concurrent access to different
/// heaps without contention.
struct Shard {
    /// Map from heap key to heap instance, protected by a mutex
    heaps: Mutex<AHashMap<usize, Box<ScrapHeap>>>,
}

// Shard can be safely sent between threads (contains only a Mutex)
unsafe impl Send for Shard {}
unsafe impl Sync for Shard {}

/// Array of 16 shards for distributing heap registry access
static SHARDS: LazyLock<Vec<Shard>> = LazyLock::new(|| {
    (0..MAX_SHARDS)
        .map(|_| Shard {
            heaps: Mutex::new(AHashMap::with_capacity(16)),
        })
        .collect()
});

// ----------------------------------------------------------------------------
// Thread-Local Cache
// ----------------------------------------------------------------------------

/// Thread-local cache entry for fast-path heap access.
struct TlsCache {
    /// Key identifying the cached heap
    key: usize,
    /// Cached pointer to the heap
    ptr: *mut ScrapHeap,
    /// Generation counter at time of caching
    generation: u64,
}

thread_local! {
    /// Thread-local storage for caching the most recently accessed heap.
    ///
    /// Bypasses shard locking for repeated allocations from the same heap.
    static RECENT_HEAP: RefCell<Option<TlsCache>> = const { RefCell::new(None) };
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Aligns an address upward to the specified alignment.
///
/// # Arguments
/// * `addr` - Address to align
/// * `align` - Alignment requirement (must be power of two)
///
/// # Returns
/// Aligned address
#[inline(always)]
fn align_up(addr: usize, align: usize) -> usize {
    (addr + (align - 1)) & !(align - 1)
}

/// Computes which shard should handle a given heap key.
///
/// Uses a simple hash function to distribute keys evenly across shards.
///
/// # Arguments
/// * `key` - Heap identifier (typically a pointer value)
///
/// # Returns
/// Shard index in range [0, MAX_SHARDS)
#[inline(always)]
fn get_shard_idx(key: usize) -> usize {
    // Mix bits to avoid alignment clustering
    let hash = key ^ (key >> 16);
    (hash >> 4) % MAX_SHARDS
}

/// Calculates appropriate region capacity for a given allocation size.
///
/// Large allocations (>128KB) get custom-sized regions, while smaller
/// allocations use the standard REGION_SIZE.
///
/// # Arguments
/// * `size` - Allocation size in bytes
/// * `align` - Alignment requirement
///
/// # Returns
/// Recommended region capacity in bytes
#[inline(always)]
fn calculate_required_capacity(size: usize, align: usize) -> usize {
    // Branchless-style: Use the standard size unless 'size' is too large.
    // This is more predictable for the instruction pipeline.
    let threshold = REGION_SIZE / 2;
    if size <= threshold {
        REGION_SIZE
    } else {
        size.saturating_add(align)
    }
}

/// Determines the empty cycle threshold for region purging.
///
/// Returns more aggressive threshold when global memory usage is high.
///
/// # Returns
/// Number of empty cycles before a region is purged
fn get_purge_threshold() -> usize {
    if TOTAL_ALLOCATED_MEM.load(Ordering::Relaxed) > GLOBAL_MEMORY_LIMIT {
        1 // Aggressive purging under memory pressure
    } else {
        EMPTY_THRESHOLD // Normal operation
    }
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Allocates memory from a ScrapHeap with specified alignment.
///
/// This is the primary interface used by the game engine. It implements
/// a fast-path/slow-path mechanism with thread-local caching.
///
/// # Arguments
/// * `sheap_ptr` - Pointer identifying the ScrapHeap instance
/// * `size` - Size of the allocation in bytes
/// * `align` - Required alignment for the allocation
///
/// # Returns
/// Pointer to allocated memory, or null pointer if allocation failed
#[inline]
pub fn sheap_alloc_align(sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
    let key = sheap_ptr as usize;

    // --- Optimized Fast Path ---
    let fast_path = RECENT_HEAP.with_borrow_mut(|cache_opt| {
        if let Some(cache) = cache_opt
            && cache.key == key
        {
            let latest_gen = GLOBAL_EVICTION_COUNT.load(Ordering::Acquire);
            if cache.generation == latest_gen {
                // Safety: Pointer is valid because generation hasn't changed
                let heap = unsafe { &mut *cache.ptr };
                let ptr = heap.alloc_aligned(size, align);
                if !ptr.is_null() {
                    return Some(ptr);
                }
            }
        }
        None
    });

    if let Some(ptr) = fast_path {
        return ptr;
    }

    // --- Slow Path ---
    let tick = GLOBAL_TICK.fetch_add(1, Ordering::Relaxed);
    let shard_idx = get_shard_idx(key);

    // Perform maintenance only on the specific shard if needed
    if (tick & 0xFFFF) == 0 {
        maintenance_cycle(tick, shard_idx);
    }

    let mut shard_lock = SHARDS[shard_idx].heaps.lock();
    let heap = shard_lock
        .entry(key)
        .or_insert_with(|| Box::new(ScrapHeap::new()));

    let heap_ptr = &mut **heap as *mut ScrapHeap;
    let current_gen = GLOBAL_EVICTION_COUNT.load(Ordering::Acquire);

    // Update heap metadata
    heap.last_access = tick;
    let result = heap.alloc_aligned(size, align);

    // Update TLS once
    RECENT_HEAP.with_borrow_mut(|cache| {
        *cache = Some(TlsCache {
            key,
            ptr: heap_ptr,
            generation: current_gen,
        });
    });

    result
}

/// Purges all allocations from a specific ScrapHeap.
///
/// Resets allocation offsets without freeing regions, making them
/// available for future allocations in the next epoch.
///
/// # Arguments
/// * `sheap_ptr` - Pointer identifying the ScrapHeap instance
#[inline]
pub fn sheap_purge(sheap_ptr: *mut c_void) {
    let key = sheap_ptr as usize;
    let tick = GLOBAL_TICK.fetch_add(1, Ordering::Relaxed);
    let shard_idx = get_shard_idx(key);

    if let Some(heap) = SHARDS[shard_idx].heaps.lock().get_mut(&key) {
        heap.last_access = tick;
        heap.purge();
    }
}

#[allow(dead_code)]
#[inline]
pub fn sheap_contains_ptr(sheap_ptr: *mut c_void, addr_ptr: *mut c_void) -> bool {
    let key = sheap_ptr as usize;
    let addr = addr_ptr as usize;
    let shard_idx = get_shard_idx(key);

    let shard_lock = SHARDS[shard_idx].heaps.lock();
    if let Some(heap) = shard_lock.get(&key) {
        return heap.get_region_index_for_addr(addr).is_some();
    }
    false
}

/// Attempts to free a specific pointer within a ScrapHeap.
///
/// Note: Since this is a bump allocator, we can only truly reclaim space
/// if the pointer being freed was the absolute last allocation made in its region.
pub fn sheap_free(sheap_ptr: *mut c_void, ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }

    let key = sheap_ptr as usize;

    // If this heap is the one this thread JUST used, we can touch it
    // without looking up shards.
    let handled = RECENT_HEAP.with_borrow(|cache_opt| {
        if let Some(cache) = cache_opt
            && cache.key == key
        {
            let latest_gen = GLOBAL_EVICTION_COUNT.load(Ordering::Acquire);

            if cache.generation == latest_gen {
                let heap = unsafe { &*cache.ptr };

                // Check bloat factor WITHOUT locking
                if heap.regions.len() > 32
                    && let Some(idx) = heap.get_region_index_for_addr(ptr as usize)
                {
                    // Safety: We only use Relaxed atomics here.
                    // No pointers are invalidated because we don't mutate the Vec.
                    heap.regions[idx]
                        .empty_cycles
                        .fetch_add(1, Ordering::Relaxed);
                    return true;
                }
            }
        }
        false
    });

    if handled {
        return;
    }

    // We cant use TLS cache, so go with regular locking
    // try_lock here really save us from shit!
    let shard_idx = get_shard_idx(key);
    if let Some(shard_lock) = SHARDS[shard_idx].heaps.try_lock()
        && let Some(heap) = shard_lock.get(&key)
        && heap.regions.len() > 32
        && let Some(idx) = heap.get_region_index_for_addr(ptr as usize)
    {
        heap.regions[idx]
            .empty_cycles
            .fetch_add(1, Ordering::Relaxed);
    }
}

// ============================================================================
// MAINTENANCE FUNCTIONS
// ============================================================================

/// Performs background maintenance: evicts dead heaps and reclaims memory.
///
/// Called periodically to prevent the heap registry from growing indefinitely
/// and to return unused memory to the system.
///
/// # Arguments
/// * `current_tick` - Current global tick value
fn maintenance_cycle(current_tick: u64, target_shard_idx: usize) {
    if let Some(mut shard_lock) = SHARDS[target_shard_idx].heaps.try_lock() {
        let prev_count = shard_lock.len();

        // Evict truly dead heaps
        shard_lock.retain(|_, heap| {
            let inactive_ticks = current_tick.saturating_sub(heap.last_access);
            inactive_ticks <= 100_000
        });

        // Incremental Purge for live but idle heaps
        for heap in shard_lock.values_mut() {
            if current_tick.saturating_sub(heap.last_access) > 5_000 {
                heap.purge();
            }
        }

        if shard_lock.len() < prev_count {
            // Signal all threads to stop using their TLS caches
            GLOBAL_EVICTION_COUNT.fetch_add(1, Ordering::SeqCst);

            // Tell mimalloc to return memory to OS
            MI_HEAP.heap_collect(false);
        }
    }
}

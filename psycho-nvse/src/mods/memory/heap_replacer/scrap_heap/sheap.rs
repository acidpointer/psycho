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
use parking_lot::{Mutex, Once};
use std::cell::RefCell;
use std::ptr::NonNull;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

// ============================================================================
// CONSTANTS
// ============================================================================

/// Size of each allocation region in bytes (128KB)
const REGION_SIZE: usize = 128 * 1024; // 128kb

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

/// How often the scavenger thread wakes up.
/// Frequent wakes with small work chunks are better than huge 30s pauses.
const SCAVENGER_SLEEP_DURATION: Duration = Duration::from_millis(500);

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
    offset: AtomicUsize,

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
            offset: AtomicUsize::new(0),
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
    fn allocate(&self, size: usize, align: usize) -> Option<NonNull<u8>> {
        let start_addr = self.start.as_ptr() as usize;
        let mut current_offset = self.offset.load(Ordering::Relaxed);

        // SMALL OBJECT FAST PATH
        // If size is small and alignment is standard, use simplified math.
        if size <= 12 && align <= 16 {
            loop {
                let data_addr = align_up(start_addr + current_offset + 4, 16);
                let next_offset = (data_addr - start_addr) + size;

                if next_offset > self.capacity {
                    return None;
                }

                match self.offset.compare_exchange_weak(
                    current_offset,
                    next_offset,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        unsafe {
                            *((data_addr - 4) as *mut u32) = size as u32;
                        }
                        return NonNull::new(data_addr as *mut u8);
                    }
                    Err(next) => current_offset = next,
                }
            }
        }

        loop {
            // Calculate the necessary padding and alignment
            let header_addr = align_up(start_addr + current_offset, 4);
            let data_addr = align_up(header_addr + 4, align);
            let requested_end = (data_addr - start_addr) + size;

            // Branchless Boundary Check
            // If requested_end > capacity, 'is_invalid' will be 0xFFFF... (all 1s)
            // otherwise it will be 0x0000... (all 0s)
            let is_invalid = ((self.capacity as isize).wrapping_sub(requested_end as isize))
                >> (std::mem::size_of::<isize>() * 8 - 1);
            
            // If invalid, we force new_offset to current_offset (no change)
            // If valid, new_offset = requested_end
            let mask = is_invalid as usize;
            let new_offset = (requested_end & !mask) | (current_offset & mask);

            // Early return if invalid (This is a single branch, but now it's highly predictable)
            if is_invalid != 0 {
                return None;
            }

            // Atomic Swap
            match self.offset.compare_exchange_weak(
                current_offset,
                new_offset,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    unsafe {
                        let size_ptr = (data_addr - 4) as *mut u32;
                        size_ptr.write(size as u32);
                    }
                    return NonNull::new(data_addr as *mut u8);
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

        // Check if pointer is within the physical bounds of this region
        if addr < start_addr + 4 || addr >= (start_addr + self.capacity) {
            return false;
        }

        // ATOMIC SAFETY: Ensure we don't read a size header that is currently being written
        let size = unsafe { *((addr - 4) as *const u32) } as usize;
        if size > self.capacity {
            return false;
        } // Corruption check

        let curr_offset = self.offset.load(Ordering::Acquire);
        if addr + size == start_addr + curr_offset {
            // Only roll back if we are definitely the top
            return self
                .offset
                .compare_exchange_weak(
                    curr_offset,
                    curr_offset - size - 4,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok();
        }
        false
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

        // If the active_index failed, don't just search forward.
        // Check if the FIRST region has space. This prevents "Region Creep."
        if self.active_index != 0
            && let Some(ptr) = self.regions[0].allocate(size, align)
        {
            self.active_index = 0;
            return ptr.as_ptr() as *mut c_void;
        }

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
        if let Some(region) = Region::new(capacity, align) {
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
        let old_count = self.regions.len();

        // Instead of just resetting, let's check if we actually SHOULD.
        // If the heap was just used 1 tick ago, purging it is dangerous
        // because the gamebryo engine often holds scrap pointers across a few micro-ticks.

        for region in &mut self.regions {
            let current_offset = region.offset.load(Ordering::Acquire);
            if current_offset == 0 {
                region.empty_cycles.fetch_add(1, Ordering::Relaxed);
            } else {
                // ONLY reset if this heap hasn't been touched in the current epoch
                region.offset.store(0, Ordering::Release);
                region.empty_cycles.store(0, Ordering::Relaxed);
            }
        }

        // 2. Aggressive Retain
        // If memory is high, we don't just reset; we drop the memory back to mimalloc.
        let purge_limit = get_purge_threshold();
        self.regions
            .retain(|r| r.empty_cycles.load(Ordering::Relaxed) < purge_limit);

        if self.regions.len() != old_count {
            self.rebuild_region_map();
            // Force a shrink to drop the Vec's internal allocation
            self.regions.shrink_to(8);
        }

        self.active_index = 0;
    }

    /// Clears memory and drops all but the primary region.
    pub fn purge_aggressive(&mut self) {
        // Drop all regions except the first one to prevent allocation churn
        // but still reclaim the bulk of the memory.
        if self.regions.len() > 1 {
            self.regions.truncate(1);
        }

        if let Some(r) = self.regions.get_mut(0) {
            r.offset.store(0, Ordering::Release);
            // We don't need to track last_alloc_size anymore because
            // the size is now stored in the memory header.
        }

        self.rebuild_region_map();
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

    #[inline]
    pub fn get_region_index_for_addr(&self, addr: usize) -> Option<usize> {
        let page = addr >> PAGE_SHIFT;

        // Most heaps only have 1-2 regions.
        // Binary search is overkill and slower than a linear scan for small N.
        if self.page_to_region.len() <= 4 {
            for &(start_page, idx) in &self.page_to_region {
                let region = &self.regions[idx];
                if page >= start_page && page <= region.end_page {
                    return Some(idx);
                }
            }
            return None;
        }

        // Fallback to binary search for massive heaps
        let idx = self.page_to_region.binary_search_by_key(&page, |&(p, _)| p);
        match idx {
            Ok(found_idx) => Some(self.page_to_region[found_idx].1),
            Err(insert_idx) => {
                if insert_idx > 0 {
                    let (_, region_idx) = self.page_to_region[insert_idx - 1];
                    let region = &self.regions[region_idx];
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
#[allow(clippy::vec_box)]
struct Shard {
    /// Map from heap key to heap instance, protected by a mutex
    heaps: Mutex<AHashMap<usize, Box<ScrapHeap>>>,

    /// Heaps to be deleted after a grace period (next tick)
    // Vec<Box<>> here is okay, it should be
    limbo: Mutex<Vec<Box<ScrapHeap>>>,
}

// Shard can be safely sent between threads (contains only a Mutex)
unsafe impl Send for Shard {}
unsafe impl Sync for Shard {}

/// Array of 16 shards for distributing heap registry access
static SHARDS: LazyLock<Vec<Shard>> = LazyLock::new(|| {
    (0..MAX_SHARDS)
        .map(|_| Shard {
            heaps: Mutex::new(AHashMap::with_capacity(512)),
            limbo: Mutex::new(Vec::with_capacity(64)),
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
// BACKGROUND SCAVENGER
// ============================================================================

static SCAVENGER_START: Once = Once::new();

static CURRENT_MAINTENANCE_SHARD: AtomicUsize = AtomicUsize::new(0);

/// Spawns the background maintenance thread.
/// Call this once during your plugin/DLL initialization.
pub fn spawn_scavenger_thread() {
    SCAVENGER_START.call_once(|| {
        thread::spawn(|| {
            debug!("ScrapHeap: Scavenger thread started.");
            loop {
                thread::sleep(SCAVENGER_SLEEP_DURATION);

                // Increment tick once per 500ms. This is plenty for "recency" tracking.
                GLOBAL_TICK.fetch_add(1, Ordering::Relaxed);
                perform_global_maintenance();
            }
        });
    });
}

fn perform_global_maintenance() {
    static LAST_TICK_CHECK: AtomicU64 = AtomicU64::new(0);
    
    let current_tick = GLOBAL_TICK.load(Ordering::Relaxed);
    let last_tick = LAST_TICK_CHECK.swap(current_tick, Ordering::Relaxed);

    // If the tick hasn't advanced since the last scavenger wake, 
    // the game main thread is likely HUNG (loading/unloading a cell).
    // Abort maintenance to avoid deleting a heap the game is about to use.
    if current_tick == last_tick {
        return; 
    }

    let shard_idx = CURRENT_MAINTENANCE_SHARD.fetch_add(1, Ordering::Relaxed) % MAX_SHARDS;
    let shard = &SHARDS[shard_idx];

    // Limbo Cleanup (Delayed Deletion)
    if let Some(mut limbo_lock) = shard.limbo.try_lock() {
        // Only drop 16 heaps at a time to prevent frame spikes
        let to_drop = limbo_lock.len().min(16);
        limbo_lock.drain(0..to_drop);
    }

    // Identify Idle Heaps
    let mut extracted = Vec::new();
    if let Some(mut shard_lock) = shard.heaps.try_lock() {
        let mut keys_to_remove = Vec::new();
        for (&key, heap) in shard_lock.iter().take(100) {
            // Increased threshold: 30 seconds of inactivity (60 scavenger cycles)
            if current_tick.saturating_sub(heap.last_access) > 60 {
                keys_to_remove.push(key);
            }
        }
        for key in keys_to_remove {
            if let Some(h) = shard_lock.remove(&key) {
                extracted.push(h);
            }
        }
    }

    // Move to Limbo (Grace Period)
    if !extracted.is_empty() {
        if let Some(mut limbo_lock) = shard.limbo.try_lock() {
            for mut h in extracted {
                h.purge_aggressive();
                limbo_lock.push(h);
            }
        }
        // Invalidate TLS so threads stop using old pointers
        GLOBAL_EVICTION_COUNT.fetch_add(1, Ordering::SeqCst);
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
    if (sheap_ptr as usize) < 0x10000 {
        return std::ptr::null_mut();
    }

    if sheap_ptr.is_null() || size == 0 {
        return std::ptr::null_mut();
    }
    let key = sheap_ptr as usize;

    // Validation check (Acquire ordering is critical here to prevent crashes)
    let current_gen = GLOBAL_EVICTION_COUNT.load(Ordering::Acquire);

    let res = RECENT_HEAP.with_borrow_mut(|cache_opt| {
        if let Some(cache) = cache_opt
            && cache.key == key
            && cache.generation == current_gen
        {
            let heap = unsafe { &mut *cache.ptr };
            return Some(heap.alloc_aligned(size, align));
        }
        None
    });
    if let Some(p) = res {
        return p;
    }

    // 2. Shard Access
    let shard_idx = get_shard_idx(key);
    let shard = &SHARDS[shard_idx];

    // INCREASE spin count. 5 is too low for NV, leading to too many fallbacks.
    // 40-100 spins is still sub-microsecond but prevents 99% of fallbacks.
    let mut shard_lock = None;
    for i in 0..40 {
        if let Some(guard) = shard.heaps.try_lock() {
            shard_lock = Some(guard);
            break;
        }
        if i < 10 {
            std::hint::spin_loop();
        } else {
            // Tell Windows to let someone else run, then try again immediately
            thread::yield_now();
        }
    }

    // If still locked, use a real lock. Fallback to MiMalloc is a LEAK
    // unless we have a complex tracking system. Better to stall for 1ms than crash/leak.
    let mut shard_lock = shard_lock.unwrap_or_else(|| {
        // On Windows, yielding is better than a hard block if we want to avoid stutters
        thread::yield_now();
        shard.heaps.lock()
    });

    let heap = shard_lock
        .entry(key)
        .or_insert_with(|| Box::new(ScrapHeap::new()));

    // Just read global tick, we update in in maintenance thread
    heap.last_access = GLOBAL_TICK.load(Ordering::Relaxed);

    let result = heap.alloc_aligned(size, align);
    let heap_ptr = &mut **heap as *mut ScrapHeap;

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
    let shard_idx = get_shard_idx(key);

    // try_lock is better here; if we can't lock it, another thread is using it
    // or purging it, so we don't want to wait and tank FPS.
    if let Some(mut shard_lock) = SHARDS[shard_idx].heaps.try_lock()
        && let Some(heap) = shard_lock.get_mut(&key)
    {
        heap.last_access = GLOBAL_TICK.load(Ordering::Relaxed);
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
    if ptr.is_null() || (ptr as usize) < 0x10000 {
        return;
    }
    let key = sheap_ptr as usize;
    let current_gen = GLOBAL_EVICTION_COUNT.load(Ordering::Acquire);

    // Only use TLS if the generation matches!
    let handled = RECENT_HEAP.with_borrow(|cache_opt| {
        if let Some(cache) = cache_opt
            && cache.key == key
            && cache.generation == current_gen
        {
            let heap = unsafe { &mut *cache.ptr };
            if let Some(idx) = heap.get_region_index_for_addr(ptr as usize) {
                heap.regions[idx].try_free(ptr);
                return true;
            }
        }
        false
    });

    if handled {
        return;
    }

    // If TLS fails, we MUST attempt a try_lock to see if this was a MiMalloc fallback.
    let shard_idx = get_shard_idx(key);
    if let Some(mut shard_lock) = SHARDS[shard_idx].heaps.try_lock()
        && let Some(heap) = shard_lock.get_mut(&key)
    {
        if let Some(idx) = heap.get_region_index_for_addr(ptr as usize) {
            heap.regions[idx].try_free(ptr);
        } else {
            // This might be a pointer from a previously dropped region or fallback.
            // Mimalloc can handle being passed pointers it doesn't own via mi_free,
            // but it's risky. For now, let the purge handle it.
        }
    }
}

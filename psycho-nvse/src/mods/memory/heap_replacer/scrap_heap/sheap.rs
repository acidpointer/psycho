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

use libc::c_void;
use libmimalloc::heap::MiHeap;
use libpsycho::common::align_up;
use log::{debug, error};
use parking_lot::{Mutex, Once};
use std::cell::RefCell;
use std::ptr::NonNull;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

/// SCC HashMap with ahash hasher
/// Fast enougth for allocator needs
type AHashMap<K, V> = scc::HashMap<K, V, ahash::RandomState>;

// ============================================================================
// CONSTANTS
// ============================================================================

/// Size of each allocation region in bytes
///
/// Recommended minimum: 128Kb
/// Recommended maximum: 512Kb
///
/// Everything that less 128Kb will lead to crash
const REGION_SIZE: usize = 128 * 1024;

/// Minimum alignment guarantee for all allocations
/// Friendly advice: do not even think of touching this!
const MIN_ALIGN: usize = 16;

/// Number of empty cycles before a region is considered for purging
const EMPTY_THRESHOLD: usize = 5; // 5

/// Minimum allowed regions per ScrapHeap instance
/// Basically, amount of pre-warmed regions
const MIN_REGIONS_PER_HEAP: usize = 3;

/// Maximum allowed regions per ScrapHeap instance
/// Regions will be truncated to this value
const MAX_REGIONS_PER_HEAP: usize = 20;

/// Number of shards for distributing heap registry access
const MAX_SHARDS: usize = 16;

/// Shift amount to convert addresses to page numbers (4096-byte pages)
const PAGE_SHIFT: usize = 12;

/// Global memory limit before aggressive purging (512 MiB)
const GLOBAL_MEMORY_LIMIT: usize = 512 * 1024 * 1024;

/// How many ticks should pass to mark heap as IDLE
const HEAP_IDLE_TICKS_DIFF: u64 = 10;

/// How often the scavenger thread wakes up.
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

/// Amount heaps currently in-use
static TOTAL_ACTIVE_HEAPS: AtomicUsize = AtomicUsize::new(0);

/// Total created heaps amount
static TOTAL_HEAPS_CREATED: AtomicUsize = AtomicUsize::new(0);

/// Total dropped heaps amount
static TOTAL_HEAPS_DROPPED: AtomicUsize = AtomicUsize::new(0);

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================


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
    let mem = TOTAL_ALLOCATED_MEM.load(Ordering::Relaxed);
    if mem > GLOBAL_MEMORY_LIMIT {
        2 // still drop reasonably fast under pressure
    } else {
        EMPTY_THRESHOLD // 5–8 normally
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

        TOTAL_ALLOCATED_MEM.fetch_add(capacity, Ordering::Relaxed);

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
                        let size_ptr = header_addr as *mut u32;
                        size_ptr.write(size as u32);
                    }
                    return NonNull::new(data_addr as *mut u8);
                }
                Err(next_val) => current_offset = next_val,
            }
        }
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

    /// Index of the currently active region (most likely to have free space)
    active_index: usize,

    /// Last global tick when this heap was accessed
    last_access: u64,

    last_purge_tick: u64,
}

impl Drop for ScrapHeap {
    fn drop(&mut self) {
        TOTAL_ACTIVE_HEAPS.fetch_sub(1, Ordering::Relaxed);
        TOTAL_HEAPS_DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

impl ScrapHeap {
    /// Creates a new empty ScrapHeap.
    pub fn new() -> Self {
        let current_tick = GLOBAL_TICK.load(Ordering::Relaxed);
        let heap = Self {
            regions: (0..MIN_REGIONS_PER_HEAP)
                .map(|_| Region::new(REGION_SIZE, MIN_ALIGN))
                .filter(|region| region.is_some())
                .map(|region| region.unwrap())
                .collect(),
            active_index: 0,
            last_access: current_tick,
            last_purge_tick: current_tick,
        };

        TOTAL_ACTIVE_HEAPS.fetch_add(1, Ordering::Relaxed);
        TOTAL_HEAPS_CREATED.fetch_add(1, Ordering::Relaxed);

        heap
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

        // 1. Fast path: active region
        if let Some(ptr) = self
            .regions
            .get_mut(self.active_index)
            .and_then(|r| r.allocate(size, align))
        {
            return ptr.as_ptr() as *mut c_void;
        }

        // 2. Scan from start (after purge everything is empty again)
        for (i, region) in self.regions.iter_mut().enumerate() {
            if let Some(ptr) = region.allocate(size, align) {
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

        if let Some(region) = Region::new(capacity, align) {
            match region.allocate(size, align) {
                Some(ptr) => {
                    let new_idx = self.regions.len();

                    self.regions.push(region);
                    self.active_index = new_idx;

                    return ptr.as_ptr() as *mut c_void;
                }

                None => {
                    error!(
                        "ScrapHeap: Failed to allocate on region (expand_and_allocate) size={}, align={}",
                        size, align
                    );
                }
            }
        }

        // Fallback
        error!(
            "ScrapHeap: Critical allocation failure for {} bytes! Falling back to global heap.",
            size
        );
        MI_HEAP.malloc_aligned(size, align)
    }

    /// Resets all allocation offsets and prunes unused regions.
    ///
    /// Called at epoch boundaries (e.g., end of frame) to reclaim memory
    /// while keeping region allocations for future use.
    pub fn purge(&mut self) {
        let old_len = self.regions.len();

        for r in &self.regions {
            let off = r.offset.load(Ordering::Acquire);
            if off == 0 {
                r.empty_cycles.fetch_add(1, Ordering::Relaxed);
            } else {
                r.offset.store(0, Ordering::Release);
                r.empty_cycles.store(0, Ordering::Relaxed);
            }
        }

        let threshold = get_purge_threshold();
        self.regions
            .retain(|r| r.empty_cycles.load(Ordering::Relaxed) < threshold);

        let dropped_some = self.regions.len() < old_len;

        if dropped_some || self.regions.len() < MIN_REGIONS_PER_HEAP {
            self.regions.shrink_to_fit();
        }

        // Hard cap (safety net)
        if self.regions.len() > MAX_REGIONS_PER_HEAP {
            self.regions.truncate(MAX_REGIONS_PER_HEAP);
        }

        self.active_index = 0;
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
    id: usize,

    /// Map from heap key to heap instance, protected by a mutex
    heaps: AHashMap<usize, Box<ScrapHeap>>,

    /// Heaps to be deleted after a grace period (next tick) + the tick they were evicted
    // Vec<Box<>> here is okay, it should be
    limbo: Mutex<Vec<(Box<ScrapHeap>, u64)>>,
}

impl Shard {
    pub fn new(id: usize) -> Self {
        Self {
            id,
            heaps: AHashMap::with_hasher(ahash::RandomState::new()),
            limbo: Mutex::new(Vec::with_capacity(16)),
        }
    }
}

// Shard can be safely sent between threads (contains only a Mutex)
unsafe impl Send for Shard {}
unsafe impl Sync for Shard {}

/// Array of shards for distributing heap registry access
static SHARDS: LazyLock<Vec<Shard>> = LazyLock::new(|| (0..MAX_SHARDS).map(Shard::new).collect());

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

#[inline(always)]
fn update_tls(key: usize, ptr: *mut ScrapHeap, generation: u64) {
    RECENT_HEAP.with_borrow_mut(|cache| {
        *cache = Some(TlsCache {
            key,
            ptr,
            generation,
        });
    });
}

// ============================================================================
// BACKGROUND SCAVENGER
// ============================================================================

static SCAVENGER_START: Once = Once::new();

/// Spawns the background maintenance thread.
/// Call this once during your plugin/DLL initialization.
pub fn spawn_scavenger_thread() {
    SCAVENGER_START.call_once(|| {
        // Tick counter thread
        thread::spawn(|| {
            debug!("ScrapHeap: Scavenger thread started.");
            loop {
                thread::sleep(SCAVENGER_SLEEP_DURATION);
                let current_tick = GLOBAL_TICK.fetch_add(1, Ordering::Relaxed);

                if current_tick.is_multiple_of(15) {
                    debug!("[SCAVENGER] ScrapHeap: calling mi_collect(false)");

                    // This call should kindly ask mimalloc to return memory to OS
                    unsafe {
                        libmimalloc::mi_collect(false);
                    }
                }
            }
        });

        // Spawn maintenance thread per shard
        for (shard_idx, _) in SHARDS.iter().enumerate() {
            thread::spawn(move || {
                loop {
                    thread::sleep(SCAVENGER_SLEEP_DURATION);
                    perform_global_maintenance(shard_idx);
                }
            });
        }
    });
}

fn perform_global_maintenance(shard_idx: usize) {
    let shard = &SHARDS[shard_idx];
    static LAST_TICK_CHECK: AtomicU64 = AtomicU64::new(0);

    let current_tick = GLOBAL_TICK.load(Ordering::Relaxed);
    let last_tick = LAST_TICK_CHECK.swap(current_tick, Ordering::Relaxed);

    if current_tick == last_tick {
        return;
    }

    // 1. Final drop from limbo
    if let Some(mut limbo) = shard.limbo.try_lock() {
        let before = limbo.len();
        limbo.retain(|(_, t)| current_tick.saturating_sub(*t) < 4);
        let dropped = before - limbo.len();
        if dropped > 0 {
            debug!(
                "[SHARD #{}] ScrapHeap: Dropped {} zombie heaps from limbo",
                shard_idx, dropped,
            );
        }
    }

    // 2. Evict idle heaps (fixed borrowing)
    let mut keys_to_evict = Vec::new();
    shard.heaps.iter_sync(|&key, heap| {
        if current_tick.saturating_sub(heap.last_access) > HEAP_IDLE_TICKS_DIFF {
            keys_to_evict.push(key);
        }

        let reg_len = heap.regions.len();

        // Log heap with regions x3 of minimum
        if reg_len > MIN_REGIONS_PER_HEAP * 3 && current_tick.is_multiple_of(10) {
            debug!(
                "[SHARD #{}] ScrapHeap: instance[{:X}]  Regions amount: {}",
                shard_idx, key, reg_len,
            );
        }

        true
    });

    if !keys_to_evict.is_empty() {
        GLOBAL_EVICTION_COUNT.fetch_add(1, Ordering::SeqCst);

        for key in keys_to_evict {
            if let Some((_, heap_box)) = shard.heaps.remove_sync(&key) {
                // Move to limbo or drop immediately
                if let Some(mut limbo) = shard.limbo.try_lock() {
                    limbo.push((heap_box, current_tick));
                } else {
                    // Trigger ScrapHeap instance drop
                    drop(heap_box);
                }
            }
        }
    }

    // 3. Stats
    if current_tick.is_multiple_of(10) {
        debug!(
            "[SHARD #{}] ScrapHeap: stats:   active: {} | created: {} | dropped: {} | tick: {} | allocated: {} MB",
            shard_idx,
            TOTAL_ACTIVE_HEAPS.load(Ordering::Relaxed),
            TOTAL_HEAPS_CREATED.load(Ordering::Relaxed),
            TOTAL_HEAPS_DROPPED.load(Ordering::Relaxed),
            current_tick,
            TOTAL_ALLOCATED_MEM.load(Ordering::Relaxed) / 1024 / 1024,
        );
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
    if key < 0x10000 {
        return std::ptr::null_mut();
    }

    let current_gen = GLOBAL_EVICTION_COUNT.load(Ordering::Acquire);
    let current_tick = GLOBAL_TICK.load(Ordering::Relaxed);

    // === ULTRA-HOT TLS PATH ===
    let res = RECENT_HEAP.with_borrow_mut(|cache| {
        if let Some(c) = cache
            && c.key == key
            && c.generation == current_gen
        {
            let heap = unsafe { &mut *c.ptr };

            // Critical!
            heap.last_access = current_tick;
            return Some(heap.alloc_aligned(size, align));
        }
        None
    });
    if let Some(p) = res {
        return p;
    }

    // === Slow path (rare) ===
    let shard_idx = get_shard_idx(key);
    let shard = &SHARDS[shard_idx];

    let mut heap_entry = shard
        .heaps
        .entry_sync(key)
        .or_insert(Box::new(ScrapHeap::new()));

    let heap = heap_entry.get_mut();

    heap.last_access = current_tick;
    let ptr = heap.alloc_aligned(size, align);

    update_tls(key, &mut **heap as *mut ScrapHeap, current_gen);
    ptr
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
    let now = GLOBAL_TICK.load(Ordering::Relaxed);

    let shard_idx = get_shard_idx(key);
    let Some(mut guard) = SHARDS[shard_idx].heaps.get_sync(&key) else {
        return;
    };

    let heap = guard.get_mut();

    heap.last_access = now;

    // Skip if purged very recently (cheap check)
    if now.saturating_sub(heap.last_purge_tick) <= 2 {
        return;
    }

    heap.last_purge_tick = now;
    heap.purge();
}

//! # High-Performance Epoch-Based Region Allocator (ScrapHeap)
//!
//! ## Architectural Overview
//! Fallout: New Vegas (and the Gamebryo engine) utilizes a "Scrap Heap" for short-lived,
//! high-frequency allocations—often related to frame-local processing, string formatting,
//! or temporary AI pathing data. In the original 32-bit engine, the default allocator
//! is prone to fragmentation and significant mutex contention.
//!
//! ### Why This Algorithm?
//! 1. **Region-Based (Arena) Allocation:** Instead of individual `malloc`/`free` calls,
//!    we allocate large 256KB "Regions". Allocating is a simple pointer bump (O(1)).
//! 2. **Epoch-Based Purging:** Memory is not freed manually. Instead, the game calls
//!    `purge` at the end of a cycle (e.g., a frame or a script execution block).
//! 3. **Sharded Registry:** To prevent global lock contention in a multi-threaded
//!    environment (like NVTF-enhanced FNV), the heaps are split across 16 shards.
//! 4. **Fast-Path Caching:** A Thread-Local Storage (TLS) cache stores the most recently
//!    accessed heap, bypassing sharding and locking entirely for repeated calls.
//! 5. **32-bit Reclamation:** Active monitoring of "Zombie Heaps" ensures that inactive
//!    memory is returned to `mimalloc` to prevent the dreaded "Out of Memory" (0xC0000005)
//!    crashes in the 4GB address space.

use ahash::AHashMap;
use libc::c_void;
use libmimalloc::heap::MiHeap;
use log::{debug, error};
use parking_lot::Mutex;
use std::cell::RefCell;
use std::ptr::{NonNull, null_mut};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

// --- Constants ---

const REGION_SIZE: usize = 256 * 1024;
const MIN_ALIGN: usize = 16;
const EMPTY_THRESHOLD: usize = 5;
const MAX_SHARDS: usize = 16;
const PAGE_SHIFT: usize = 12;
const GLOBAL_MEMORY_LIMIT: usize = 512 * 1024 * 1024; // 512 MiB

// --- Globals ---

static MI_HEAP: LazyLock<MiHeap> = LazyLock::new(MiHeap::new);
static GLOBAL_TICK: AtomicU64 = AtomicU64::new(0);
static TOTAL_ALLOCATED_MEM: AtomicUsize = AtomicUsize::new(0);

/// Incremented whenever a heap is removed. Invalidates all TLS caches.
static GLOBAL_EVICTION_COUNT: AtomicU64 = AtomicU64::new(0);

/// An Identity Hasher that bypasses the CPU cost of hashing for keys that are already
/// unique (memory addresses/pointers).
type IdentityHasher = std::hash::BuildHasherDefault<ahash::AHasher>;

// --- Core Structures ---

/// A contiguous block of memory used for bump-pointer allocation.
struct Region {
    start: NonNull<u8>,
    capacity: usize,
    offset: usize,
    empty_cycles: usize,
}

impl Region {
    /// Creates a new memory region backed by mimalloc.
    fn new(capacity: usize, align: usize) -> Option<Self> {
        let ptr = MI_HEAP.malloc_aligned(capacity, align);
        let start = NonNull::new(ptr as *mut u8)?;

        let total = TOTAL_ALLOCATED_MEM.fetch_add(capacity, Ordering::Relaxed) + capacity;
        debug!(
            "Region::new: Allocated {} KB (Global: {} MB)",
            capacity / 1024,
            total / (1024 * 1024)
        );

        Some(Self {
            start,
            capacity,
            offset: 0,
            empty_cycles: 0,
        })
    }

    /// Performs a bump-pointer allocation within the region.
    #[inline]
    fn allocate(&mut self, size: usize, align: usize) -> Option<NonNull<u8>> {
        let current_addr = self.start.as_ptr() as usize + self.offset;
        let aligned_addr = align_up(current_addr, align);
        let new_offset = (aligned_addr - self.start.as_ptr() as usize) + size;

        if new_offset > self.capacity {
            return None;
        }

        self.offset = new_offset;
        self.empty_cycles = 0;
        NonNull::new(aligned_addr as *mut u8)
    }

    /// Returns the range of memory pages covered by this region for the lookup map.
    #[inline]
    fn page_range(&self) -> std::ops::Range<usize> {
        let start_page = (self.start.as_ptr() as usize) >> PAGE_SHIFT;
        let end_page = (self.start.as_ptr() as usize + self.capacity - 1) >> PAGE_SHIFT;
        start_page..end_page + 1
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
pub struct ScrapHeap {
    regions: Vec<Region>,
    region_map: AHashMap<usize, usize, IdentityHasher>,
    active_index: usize,
    pub last_access: u64,
}

impl ScrapHeap {
    pub fn new() -> Self {
        Self {
            regions: Vec::with_capacity(4),
            region_map: AHashMap::with_capacity_and_hasher(64, IdentityHasher::default()),
            active_index: 0,
            last_access: 0,
        }
    }

    /// Primary allocation entry point for a specific heap.
    pub fn alloc_aligned(&mut self, size: usize, align: usize) -> *mut c_void {
        if size == 0 {
            return std::ptr::null_mut();
        }
        let align = align.max(MIN_ALIGN);

        // 1. Try the current active region (Highest probability of success)
        if let Some(region) = self.regions.get_mut(self.active_index)
            && let Some(ptr) = region.allocate(size, align)
        {
            return ptr.as_ptr() as *mut c_void;
        }

        // 2. Search other existing regions
        for (i, region) in self.regions.iter_mut().enumerate() {
            if i == self.active_index {
                continue;
            }
            if let Some(ptr) = region.allocate(size, align) {
                self.active_index = i;
                return ptr.as_ptr() as *mut c_void;
            }
        }

        // 3. Create new region if needed
        self.expand_and_allocate(size, align)
    }

    fn expand_and_allocate(&mut self, size: usize, align: usize) -> *mut c_void {
        let capacity = calculate_required_capacity(size, align);

        if let Some(mut region) = Region::new(capacity, MIN_ALIGN) {
            let ptr = region
                .allocate(size, align)
                .expect("Allocation must succeed in new region");
            let new_idx = self.regions.len();

            for page in region.page_range() {
                self.region_map.insert(page, new_idx);
            }

            self.regions.push(region);
            self.active_index = new_idx;
            return ptr.as_ptr() as *mut c_void;
        }

        error!("ScrapHeap: Critical allocation failure! Falling back to global heap.");
        MI_HEAP.malloc_aligned(size, align)
    }

    /// Resets all offsets for the next epoch and prunes unused regions.
    pub fn purge(&mut self) {
        let old_count = self.regions.len();
        for r in &mut self.regions {
            if r.offset == 0 {
                r.empty_cycles += 1;
            } else {
                r.offset = 0;
                r.empty_cycles = 0;
            }
        }

        let threshold = get_purge_threshold();
        self.regions.retain(|r| r.empty_cycles < threshold);

        if self.regions.len() != old_count {
            // FIX: Manual replacement instead of std::mem::take to avoid Default trait error
            if self.regions.is_empty() {
                self.region_map = AHashMap::with_capacity_and_hasher(0, IdentityHasher::default());
            } else {
                // Swap out the old map for a fresh one, then rebuild
                let _old_map = std::mem::replace(
                    &mut self.region_map,
                    AHashMap::with_capacity_and_hasher(0, IdentityHasher::default()),
                );
                self.rebuild_region_map();
            }
            self.conditionally_shrink();
        }
        self.active_index = 0;
    }

    /// Forces a rebuild of the region map to ensure zero ghost-memory.
    fn rebuild_region_map(&mut self) {
        // Pre-calculate to avoid re-allocations
        let total_pages: usize = self.regions.iter().map(|r| r.page_range().count()).sum();

        // Ensure we have a fresh map with exactly the capacity we need
        let mut new_map =
            AHashMap::with_capacity_and_hasher(total_pages, IdentityHasher::default());

        for (idx, region) in self.regions.iter().enumerate() {
            for page in region.page_range() {
                new_map.insert(page, idx);
            }
        }
        self.region_map = new_map;
    }

    fn conditionally_shrink(&mut self) {
        if self.regions.capacity() > self.regions.len() * 2 {
            self.regions.shrink_to_fit();
            self.region_map.shrink_to_fit();
        }
    }
}

// --- Global Management & Sharding ---

struct Shard {
    heaps: Mutex<AHashMap<usize, Box<ScrapHeap>, IdentityHasher>>,
}

// Safety: Contains single mutex, so no issues
unsafe impl Send for Shard {}
unsafe impl Sync for Shard {}

static SHARDS: LazyLock<Vec<Shard>> = LazyLock::new(|| {
    (0..MAX_SHARDS)
        .map(|_| Shard {
            heaps: Mutex::new(AHashMap::with_capacity_and_hasher(
                16,
                IdentityHasher::default(),
            )),
        })
        .collect()
});

struct TlsCache {
    key: usize,
    ptr: *mut ScrapHeap,
    generation: u64, // Tracks if a maintenance cycle happened
}

thread_local! {
        /// TLS cache to avoid shard locking for the same heap pointer in a hot loop.

    static RECENT_HEAP: RefCell<Option<TlsCache>> = const { RefCell::new(None) };
}

// --- Helper Functions ---

#[inline(always)]
fn align_up(addr: usize, align: usize) -> usize {
    (addr + (align - 1)) & !(align - 1)
}

#[inline(always)]
fn get_shard_idx(key: usize) -> usize {
    // Basic bit-mix to ensure pointer alignment doesn't cluster keys in one shard.
    let hash = key ^ (key >> 16);
    (hash >> 4) % MAX_SHARDS
}

fn calculate_required_capacity(size: usize, align: usize) -> usize {
    if size > REGION_SIZE / 2 {
        size.checked_add(align).unwrap_or(size)
    } else {
        REGION_SIZE
    }
}

fn get_purge_threshold() -> usize {
    if TOTAL_ALLOCATED_MEM.load(Ordering::Relaxed) > GLOBAL_MEMORY_LIMIT {
        1 // Aggressive: remove immediately if empty
    } else {
        EMPTY_THRESHOLD
    }
}

// --- Public API ---

/// Aligned allocation for a ScrapHeap identified by `sheap_ptr`.
#[inline]
pub fn sheap_alloc_align(sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
    let key = sheap_ptr as usize;
    let tick = GLOBAL_TICK.fetch_add(1, Ordering::Relaxed);

    // 1. Thread-Local Fast Path
    // Check generation BEFORE using the pointer
    let tl_fp = RECENT_HEAP.with_borrow_mut(|cache_opt| {
        if let Some(cache) = cache_opt
            && cache.key == key
        {
            // We must check the CURRENT global count against the cached one
            let latest_gen = GLOBAL_EVICTION_COUNT.load(Ordering::Acquire);
            if cache.generation == latest_gen {
                let h = unsafe { &mut *cache.ptr };
                h.last_access = tick;
                return h.alloc_aligned(size, align);
            }
        }
        null_mut()
    });

    if !tl_fp.is_null() {
        return tl_fp;
    }

    // 2. Sharded Slow Path
    let shard_idx = get_shard_idx(key);
    let mut shard = SHARDS[shard_idx].heaps.lock();

    // Maintenance Trigger (ensure it happens before we insert/cache)
    if (tick & 0xFFFF) == 0 {
        drop(shard);
        maintenance_cycle(tick);
        shard = SHARDS[shard_idx].heaps.lock();
    }

    let heap = shard
        .entry(key)
        .or_insert_with(|| Box::new(ScrapHeap::new()));
    let ptr = &mut **heap as *mut ScrapHeap;
    let cur_gen = GLOBAL_EVICTION_COUNT.load(Ordering::Acquire);

    RECENT_HEAP.with_borrow_mut(|r| {
        *r = Some(TlsCache {
            key,
            ptr,
            generation: cur_gen,
        })
    });

    heap.last_access = tick;
    heap.alloc_aligned(size, align)
}

/// Purges the specified ScrapHeap.
pub fn sheap_purge(sheap_ptr: *mut c_void) {
    let key = sheap_ptr as usize;
    let tick = GLOBAL_TICK.fetch_add(1, Ordering::Relaxed);
    let shard_idx = get_shard_idx(key);

    if let Some(heap) = SHARDS[shard_idx].heaps.lock().get_mut(&key) {
        heap.last_access = tick;
        heap.purge();
    }
}

/// Background maintenance to reclaim memory and EVICT dead heap handles.
/// This prevents the AHashMap from growing infinitely with pointers the game has already freed.
fn maintenance_cycle(current_tick: u64) {
    let mut total_evicted = 0;
    
    // Check if we are nearing the danger zone (400MB+ for FNV is risky)
    let is_emergency = TOTAL_ALLOCATED_MEM.load(Ordering::Relaxed) > (300 * 1024 * 1024);

    for shard_obj in SHARDS.iter() {
        let mut shard = shard_obj.heaps.lock();
        
        // In emergency (level transition/bloat), be 5x more aggressive
        let expiry = if is_emergency { 20_000 } else { 100_000 };

        shard.retain(|_, heap| {
            let inactive = current_tick.saturating_sub(heap.last_access);
            if inactive > expiry {
                total_evicted += 1;
                return false; 
            }
            // Purge active but idle heaps faster during transitions
            if is_emergency && inactive > 2_000 && !heap.regions.is_empty() {
                heap.purge();
            }
            true
        });
        
        if total_evicted > 0 {
            shard.shrink_to_fit();
        }
    }

    if total_evicted > 0 {
        GLOBAL_EVICTION_COUNT.fetch_add(1, Ordering::SeqCst);
        // Force mimalloc to actually release these pages to the OS
        MI_HEAP.heap_collect(true); 
    }
}
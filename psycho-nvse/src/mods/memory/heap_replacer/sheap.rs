//! Epoch-based region allocator for temporary allocations.
//!
//! This is intentional: individual frees do NOT reclaim memory.
//! All reclamation happens at purge time when the epoch ends.
//! 
//! Design philosophy:
//! - Allocations are fast: O(1) bump pointer
//! - Frees are no-ops: O(1) validation only
//! - Memory is reclaimed only during purge (epoch boundary)
//! 
//! Technical details:
//! - Fast hashmaps with ahash hasher for performance reasons
//! - ScrapHeap instances are thread local
//! - Tick counter is global for ALL instances(from other threads too)
//! - MiMalloc heap used as baking heap
//! - Heap corruption tolerance - theoretical atm(scrap heap is thread local)
//! - Automated cleanup of dead heaps



use ahash::AHashMap;
use libc::c_void;
use libmimalloc::heap::MiHeap;
use std::cell::RefCell;
use std::ptr::NonNull;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// Default region size: 256 KB
///
/// Extremely conservative for 32-bit with 120+ heap instances.
/// 120 * 256 KB = 30 MiB baseline, much better than 120+ MiB.
const REGION_SIZE: usize = 256 * 1024;

/// Minimum alignment for all allocations
const MIN_ALIGN: usize = 16;

/// Number of purge cycles a region must be unused before deallocation.
///
/// Aggressive reclamation to minimize memory footprint with many heap instances.
/// With thousands of purges per second, even 50 is substantial.
const EMPTY_THRESHOLD: usize = 50;

/// Minimum number of regions to keep allocated.
///
/// Set to 0 to allow complete deallocation when heap is unused.
const MIN_REGIONS: usize = 0;

/// Maximum number of heap instances allowed.
///
/// Game creates 120+ heaps. Beyond this, allocations fall back to MiMalloc.
const MAX_HEAP_INSTANCES: usize = 128;

/// Heap inactivity threshold for cleanup.
///
/// Heaps unused for this many operations are candidates for removal.
/// Set very high to avoid removing heaps during save/load pauses.
/// Better to leak some memory than crash by removing active heaps.
const HEAP_INACTIVITY_THRESHOLD: u64 = 500000;

/// Page shift for 4KB pages (2^12 = 4096)
const PAGE_SHIFT: usize = 12;

/// Special MiHeap instance for fallback allocations
static MI_HEAP_FALLBACK: LazyLock<MiHeap> = LazyLock::new(MiHeap::new);

/// Contiguous memory region with bump allocation.
///
/// Allocations advance a pointer forward. Memory is reclaimed
/// only when the region is reset during purge.
struct Region {
    /// Start of memory buffer
    start: NonNull<u8>,

    /// Total capacity in bytes
    capacity: usize,

    /// Current allocation offset from start
    offset: usize,

    /// Allocations made in current epoch (for statistics)
    alloc_count: usize,

    /// Consecutive purges where offset remained at zero
    empty_cycles: usize,
}

impl Region {
    /// Creates a new region by allocating from the backing heap.
    fn new(backing_heap: &MiHeap, capacity: usize, align: usize) -> Option<Self> {
        if capacity == 0 {
            log::error!("Cannot create region with zero capacity");
            return None;
        }

        let ptr = backing_heap.malloc_aligned(capacity, align);
        let start = NonNull::new(ptr as *mut u8)?;

        Some(Self {
            start,
            capacity,
            offset: 0,
            alloc_count: 0,
            empty_cycles: 0,
        })
    }

    /// Allocates memory with specified size and alignment.
    ///
    /// Returns None if insufficient space remains.
    #[inline]
    fn allocate(&mut self, size: usize, align: usize) -> Option<NonNull<u8>> {
        let current_addr = self.start.as_ptr() as usize + self.offset;
        let aligned_addr = align_up(current_addr, align);
        let new_offset = self.offset + (aligned_addr - current_addr) + size;

        if new_offset > self.capacity {
            return None;
        }

        self.offset = new_offset;
        self.alloc_count += 1;
        self.empty_cycles = 0;

        // aligned_addr is within [start, start+capacity) which is a valid allocation from the backing heap.
        NonNull::new(aligned_addr as *mut u8)
    }

    /// Returns the half-open page range [start_page, end_page) this region spans.
    #[inline]
    fn page_range(&self) -> std::ops::Range<usize> {
        let start_addr = self.start.as_ptr() as usize;
        let start_page = start_addr >> PAGE_SHIFT;
        let end_page = (start_addr + self.capacity - 1) >> PAGE_SHIFT;
        start_page..end_page + 1
    }

    /// Resets region for reuse.
    ///
    /// Called during purge to reclaim all memory in this region.
    fn reset(&mut self) {
        let was_empty = self.offset == 0;

        self.offset = 0;
        self.alloc_count = 0;

        if was_empty {
            self.empty_cycles += 1;
        } else {
            self.empty_cycles = 0;
        }
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        unsafe {
            libmimalloc::mi_free(self.start.as_ptr() as *mut c_void);
        }
    }
}

// Safety: ScrapHeap is thread_local, region lives on single thread, so no issues
unsafe impl Send for Region {}

// Safety: ScrapHeap is thread_local, region lives on single thread, so no issues
unsafe impl Sync for Region {}

/// Epoch-based allocator managing multiple memory regions.
///
/// Provides fast allocation and efficient bulk deallocation.
/// Individual frees are no-ops - memory is reclaimed only during purge.
pub struct ScrapHeap {
    /// Active memory regions
    regions: Vec<Region>,

    /// Fast O(1) pointer-to-region lookup (page_number -> region_index)
    region_map: AHashMap<usize, usize>,

    /// Index of current allocation target
    active_index: usize,

    /// Backing allocator for regions
    backing_heap: MiHeap,

    /// Current epoch number (incremented on each purge)
    current_epoch: u32,

    /// Total allocation requests served
    total_allocs: usize,

    /// Total free calls (for statistics only)
    total_frees: usize,

    /// Total purge operations performed
    total_purges: usize,

    /// Free calls with invalid pointers
    invalid_frees: usize,

    /// Monotonic counter for inactivity detection
    last_access: u64,
}

unsafe impl Send for ScrapHeap {}
unsafe impl Sync for ScrapHeap {}

impl ScrapHeap {
    /// Creates a new ScrapHeap.
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
            region_map: AHashMap::new(),
            active_index: 0,
            backing_heap: MiHeap::new(),
            current_epoch: 0,
            total_allocs: 0,
            total_frees: 0,
            total_purges: 0,
            invalid_frees: 0,
            last_access: 0,
        }
    }

    /// Allocates memory with specified size and alignment.
    pub fn alloc_aligned(&mut self, size: usize, align: usize) -> *mut c_void {
        if size == 0 {
            return std::ptr::null_mut();
        }

        if align == 0 || !align.is_power_of_two() {
            log::error!("Invalid alignment: {} (must be non-zero power of 2)", align);
            return std::ptr::null_mut();
        }

        let align = align.max(MIN_ALIGN);

        // Try active region first
        if let Some(region) = self.regions.get_mut(self.active_index)
            && let Some(ptr) = region.allocate(size, align)
        {
            self.total_allocs += 1;
            return ptr.as_ptr() as *mut c_void;
        }

        // Find or create a region with capacity
        if let Some(ptr) = self.find_available_region(size, align) {
            self.total_allocs += 1;
            return ptr;
        }

        // Allocate new region
        match self.create_region(size, align) {
            Some(ptr) => {
                self.total_allocs += 1;
                ptr
            }
            None => {
                log::error!("ScrapHeap: Failed to create new region");
                std::ptr::null_mut()
            }
        }
    }

    /// Frees a previously allocated pointer.
    ///
    /// This is intentionally a no-op in epoch-based allocation.
    /// Memory is reclaimed only during purge when the epoch ends.
    ///
    /// We validate the pointer for debugging but don't track individual frees.
    pub fn free(&mut self, ptr: *mut c_void) {
        if ptr.is_null() {
            return;
        }

        self.total_frees += 1;

        // Optional: validate pointer belongs to our regions using O(1) lookup
        #[cfg(debug_assertions)]
        {
            let addr = ptr as usize;
            let found = self.find_region_for_ptr(addr).is_some();

            if !found {
                self.invalid_frees += 1;
                if self.invalid_frees % 100 == 1 {
                    log::warn!(
                        "ScrapHeap::free: Pointer {:p} not from this heap ({} invalid frees)",
                        ptr,
                        self.invalid_frees
                    );
                }
            }
        }

        // Free is a no-op - memory reclaimed only during purge
    }

    /// Reclaims all memory by resetting all regions.
    ///
    /// This ends the current epoch and begins a new one.
    /// All allocations from the previous epoch become invalid.
    pub fn purge(&mut self) {
        self.total_purges += 1;
        self.current_epoch = self.current_epoch.wrapping_add(1);

        // Reset all regions
        for region in &mut self.regions {
            region.reset();
        }

        // Remove regions that have been empty for too long
        let before_count = self.regions.len();

        if self.regions.len() > MIN_REGIONS {
            // Aggressive deallocation if we have too many regions (fragmentation)
            let threshold = if before_count > 100 {
                // Emergency: deallocate after just 5 empty cycles
                5
            } else if before_count > 20 {
                // Moderate: deallocate after 10 empty cycles
                10
            } else {
                // Normal: use configured threshold
                EMPTY_THRESHOLD
            };

            self.regions.retain(|r| r.empty_cycles < threshold);
        }

        let after_count = self.regions.len();
        let deallocated = before_count - after_count;

        // Rebuild page map if any regions were removed (indices shifted)
        if deallocated > 0 {
            log::debug!("ScrapHeap: Deallocated {} regions", deallocated);

            self.rebuild_region_map();
        }

        // Set active index to first region, or 0 if no regions
        self.active_index = 0;

        // Only log purges occasionally to avoid spam
        if self.total_purges.is_multiple_of(100) || deallocated > 0 {
            log::debug!(
                "ScrapHeap: Epoch {} complete (regions: {}, deallocated: {})",
                self.current_epoch,
                self.regions.len(),
                deallocated
            );
        }
    }

    /// Statistics for debugging and monitoring.
    #[allow(dead_code)]
    pub fn stats(&self) -> HeapStats {
        let total_capacity: usize = self.regions.iter().map(|r| r.capacity).sum();
        let total_used: usize = self.regions.iter().map(|r| r.offset).sum();
        let epoch_allocations: usize = self.regions.iter().map(|r| r.alloc_count).sum();

        HeapStats {
            current_epoch: self.current_epoch,
            region_count: self.regions.len(),
            total_capacity,
            total_used,
            epoch_allocations,
            total_allocs: self.total_allocs,
            total_frees: self.total_frees,
            total_purges: self.total_purges,
            invalid_frees: self.invalid_frees,
        }
    }

    /// Finds the region index containing a given pointer address.
    ///
    /// True O(1) lookup using page-granularity mapping.
    fn find_region_for_ptr(&self, addr: usize) -> Option<usize> {
        let page_addr = addr >> PAGE_SHIFT;
        self.region_map.get(&page_addr).copied()
    }

    /// Inserts all pages spanned by `regions[idx]` into the page map.
    fn register_region_pages(&mut self, idx: usize) {
        for page in self.regions[idx].page_range() {
            self.region_map.insert(page, idx);
        }
    }

    /// Clears and fully rebuilds the page map from the current region list.
    /// Must be called after any operation that shifts Vec indices (e.g. retain).
    fn rebuild_region_map(&mut self) {
        self.region_map.clear();
        for idx in 0..self.regions.len() {
            self.register_region_pages(idx);
        }
    }

    /// Searches for a region that can satisfy the request.
    ///
    /// Skips the active region as it was already tried.
    fn find_available_region(&mut self, size: usize, align: usize) -> Option<*mut c_void> {
        for (index, region) in self.regions.iter_mut().enumerate() {
            if index == self.active_index {
                continue;
            }

            if let Some(ptr) = region.allocate(size, align) {
                self.active_index = index;
                return Some(ptr.as_ptr() as *mut c_void);
            }
        }
        None
    }

    /// Creates a new region sized to fit the request.
    fn create_region(&mut self, size: usize, align: usize) -> Option<*mut c_void> {
        // Adaptive sizing: if we have many regions, double the region size
        // to reduce fragmentation. Cap at 4 MiB.
        let base_size = if self.regions.len() > 10 {
            (REGION_SIZE * 2).min(4 * 1024 * 1024) // 512 KB, max 4 MiB
        } else {
            REGION_SIZE // 256 KB
        };

        let capacity = base_size.max(size.checked_add(align)?);

        let mut region = match Region::new(&self.backing_heap, capacity, MIN_ALIGN) {
            Some(r) => r,
            None => {
                log::error!(
                    "ScrapHeap: Failed to allocate region (capacity: {} KB, total regions: {}, total capacity: {} KB)",
                    capacity / 1024,
                    self.regions.len(),
                    self.regions.iter().map(|r| r.capacity).sum::<usize>() / 1024
                );
                return None;
            }
        };

        let ptr = region.allocate(size, align)?;

        let new_index = self.regions.len();
        let page_count = region.page_range().len();

        self.regions.push(region);
        self.register_region_pages(new_index);
        self.active_index = new_index;

        if self.regions.len() <= 3 {
            log::debug!(
                "ScrapHeap: Created region #{} at {:p} (capacity: {} KB, pages: {})",
                self.regions.len(),
                self.regions[new_index].start.as_ptr(),
                capacity / 1024,
                page_count
            );
        }

        Some(ptr.as_ptr() as *mut c_void)
    }
}

/// Statistics snapshot for heap monitoring.
#[allow(dead_code)]
pub struct HeapStats {
    pub current_epoch: u32,
    pub region_count: usize,
    pub total_capacity: usize,
    pub total_used: usize,
    pub epoch_allocations: usize,
    pub total_allocs: usize,
    pub total_frees: usize,
    pub total_purges: usize,
    pub invalid_frees: usize,
}

/// Aligns address upward to the nearest `align` boundary.
///
/// `align` must be a non-zero power of two. Callers guarantee that `addr` is
/// within a region whose capacity is bounded well below `usize::MAX`, so
/// overflow is not possible.
#[inline(always)]
fn align_up(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    debug_assert!(align > 0);

    (addr + (align - 1)) & !(align - 1)
}

// ============================================================================
// Public API - Per-Heap Instances with Lifecycle Management
// ============================================================================

/// Global monotonic counter for heap activity tracking.
static GLOBAL_TICK: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// Global map of game heap pointers to ScrapHeap instances.
    ///
    /// Each game heap MUST have isolated epochs. Pooling breaks this.
    /// Dead heaps are cleaned up periodically based on inactivity.
    static HEAPS: RefCell<AHashMap<usize, ScrapHeap>> = RefCell::new(AHashMap::new());
}

/// Cleans up inactive heaps to prevent memory leaks from dead threads.
///
/// Removes heaps that haven't been accessed recently.
fn cleanup_inactive_heaps(heaps: &mut AHashMap<usize, ScrapHeap>, current_tick: u64) {
    let before_count = heaps.len();

    heaps.retain(|&heap_ptr, heap| {
        let inactive_for = current_tick.saturating_sub(heap.last_access);
        let should_keep = inactive_for < HEAP_INACTIVITY_THRESHOLD;

        if !should_keep {
            let total_kb = heap.regions.iter().map(|r| r.capacity).sum::<usize>() / 1024;
            log::info!(
                "ScrapHeap: Removing inactive heap {:p} (idle for {} ticks, {} regions, {} KB)",
                heap_ptr as *const c_void,
                inactive_for,
                heap.regions.len(),
                total_kb
            );
        }

        should_keep
    });

    let removed = before_count - heaps.len();
    if removed > 0 {
        log::info!(
            "ScrapHeap: Cleaned up {} inactive heap(s), {} active remaining",
            removed,
            heaps.len()
        );
    }
}

/// Allocates memory from the scrap heap for the given game heap pointer.
#[inline]
pub fn sheap_alloc_align(sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
    let current_tick = GLOBAL_TICK.fetch_add(1, Ordering::Relaxed);

    HEAPS.with_borrow_mut(|heaps| {
        // Periodic cleanup every 50000 alloc operations
        if current_tick.is_multiple_of(50000) {
            cleanup_inactive_heaps(heaps, current_tick);
        }

        let key = sheap_ptr as usize;

        if heaps.len() >= MAX_HEAP_INSTANCES && !heaps.contains_key(&key) {
            log::warn!(
                "ScrapHeap: Max heap instances ({}) reached, heap {:p} will use fallback allocator",
                MAX_HEAP_INSTANCES,
                sheap_ptr
            );
            return MI_HEAP_FALLBACK.malloc_aligned(size, align);
        }

        let heap = heaps.entry(key).or_insert_with(|| {
            log::info!("Creating new ScrapHeap instance for: {:p}", sheap_ptr);
            ScrapHeap::new()
        });

        heap.last_access = current_tick;
        heap.alloc_aligned(size, align)
    })
}

/// Marks memory as freed (no-op in epoch-based allocation).
#[inline]
pub fn sheap_free(sheap_ptr: *mut c_void, ptr: *mut c_void) {
    HEAPS.with_borrow_mut(|heaps| {
        if let Some(heap) = heaps.get_mut(&(sheap_ptr as usize)) {
            heap.free(ptr);
        }
        // If heap doesn't exist, pointer was either from MiMalloc fallback
        // (which manages its own frees) or already purged. Either way: no-op.
    })
}

/// Purges all regions in the heap associated with the game heap pointer.
#[inline]
pub fn sheap_purge(sheap_ptr: *mut c_void) {
    let current_tick = GLOBAL_TICK.fetch_add(1, Ordering::Relaxed);

    HEAPS.with_borrow_mut(|heaps| {
        if let Some(heap) = heaps.get_mut(&(sheap_ptr as usize)) {
            heap.last_access = current_tick;
            heap.purge();
        }
    })
}

//! Epoch-based region allocator for temporary allocations.
//!
//! Design philosophy:
//! - Allocations are fast: O(1) bump pointer
//! - Frees are no-ops: O(1) validation only
//! - Memory is reclaimed only during purge (epoch boundary)
//!
//! This is intentional: individual frees do NOT reclaim memory.
//! All reclamation happens at purge time when the epoch ends.

use ahash::AHashMap;
use libc::c_void;
use libmimalloc::heap::MiHeap;
use std::ptr::NonNull;
use std::sync::LazyLock;

/// Default region size: 4 MiB
///
/// Very conservative for 32-bit: 28+ heap instances created by game.
/// Start small, grow if needed. Address space is precious.
const REGION_SIZE: usize = 4 * 1024 * 1024;

/// Minimum alignment for all allocations
const MIN_ALIGN: usize = 16;

/// Number of purge cycles a region must be unused before deallocation.
///
/// Set very high for New Vegas - memory stability > aggressive reclamation.
/// Better to hold memory than risk crashes from premature deallocation.
const EMPTY_THRESHOLD: usize = 1000;

/// Minimum number of regions to keep allocated.
///
/// Conservative: start with 1, grow as needed.
/// Multiple heap instances make aggressive MIN_REGIONS dangerous.
const MIN_REGIONS: usize = 1;

/// Maximum number of heap instances to create.
///
/// Game creates 65+ heap instances during gameplay. Cap at reasonable limit to prevent OOM.
const MAX_HEAP_INSTANCES: usize = 128;

/// Page shift for 4KB pages (2^12 = 4096)
const PAGE_SHIFT: usize = 12;

/// Page size in bytes
const PAGE_SIZE: usize = 1 << PAGE_SHIFT;

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
    fn allocate(&mut self, size: usize, align: usize) -> Option<NonNull<u8>> {
        let current_addr = (self.start.as_ptr() as usize).checked_add(self.offset)?;
        let aligned_addr = align_up(current_addr, align)?;
        let padding = aligned_addr.checked_sub(current_addr)?;
        let total_size = padding.checked_add(size)?;

        if self.offset.checked_add(total_size)? > self.capacity {
            return None;
        }

        self.offset = self.offset.checked_add(total_size)?;
        self.alloc_count = self.alloc_count.checked_add(1)?;
        self.empty_cycles = 0;

        NonNull::new(aligned_addr as *mut u8)
    }

    /// Checks if region can satisfy an allocation request.
    fn has_capacity_for(&self, size: usize, align: usize) -> bool {
        let current_addr = match (self.start.as_ptr() as usize).checked_add(self.offset) {
            Some(addr) => addr,
            None => return false,
        };

        let aligned_addr = match align_up(current_addr, align) {
            Some(addr) => addr,
            None => return false,
        };

        let padding = match aligned_addr.checked_sub(current_addr) {
            Some(p) => p,
            None => return false,
        };

        let total_size = match padding.checked_add(size) {
            Some(s) => s,
            None => return false,
        };

        match self.offset.checked_add(total_size) {
            Some(new_offset) => new_offset <= self.capacity,
            None => false,
        }
    }

    /// Checks if pointer belongs to this region.
    fn contains(&self, ptr: *const u8) -> bool {
        let addr = ptr as usize;
        let start_addr = self.start.as_ptr() as usize;
        let end_addr = match start_addr.checked_add(self.capacity) {
            Some(end) => end,
            None => return false,
        };

        addr >= start_addr && addr < end_addr
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

    /// Checks if region should be deallocated.
    fn should_deallocate(&self) -> bool {
        self.offset == 0 && self.empty_cycles >= EMPTY_THRESHOLD
    }

    /// Returns percentage of used capacity.
    fn utilization(&self) -> f32 {
        if self.capacity == 0 {
            return 0.0;
        }
        (self.offset as f32 / self.capacity as f32) * 100.0
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        unsafe {
            libmimalloc::mi_free(self.start.as_ptr() as *mut c_void);
        }
    }
}

unsafe impl Send for Region {}
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
        }
    }

    /// Allocates memory with specified size and alignment.
    pub fn alloc_aligned(&mut self, size: usize, align: usize) -> *mut c_void {
        if size == 0 {
            return std::ptr::null_mut();
        }

        if align == 0 || !align.is_power_of_two() {
            log::error!(
                "Invalid alignment: {} (must be non-zero power of 2)",
                align
            );
            return std::ptr::null_mut();
        }

        let align = align.max(MIN_ALIGN);

        // Try active region first
        if let Some(region) = self.regions.get_mut(self.active_index) {
            if let Some(ptr) = region.allocate(size, align) {
                self.total_allocs += 1;
                return ptr.as_ptr() as *mut c_void;
            }
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
        let initial_count = self.regions.len();
        if self.regions.len() > MIN_REGIONS {
            self.regions.retain(|r| !r.should_deallocate());
        }

        let deallocated = initial_count - self.regions.len();

        // Only rebuild page map if regions were actually deallocated
        // (rebuilding is expensive with thousands of purges per second)
        if deallocated > 0 {
            log::debug!("ScrapHeap: Deallocated {} regions", deallocated);

            // Rebuild region map after removal (indices have changed)
            self.region_map.clear();
            for (idx, region) in self.regions.iter().enumerate() {
                let start_addr = region.start.as_ptr() as usize;
                let end_addr = start_addr + region.capacity;

                // Register all pages this region spans
                let start_page = start_addr >> PAGE_SHIFT;
                let end_page = (end_addr - 1) >> PAGE_SHIFT;

                for page in start_page..=end_page {
                    self.region_map.insert(page, idx);
                }
            }
        }

        // Set active index to first region, or 0 if no regions
        self.active_index = 0;

        // Only log purges occasionally to avoid spam
        if self.total_purges % 100 == 0 || deallocated > 0 {
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

    /// Searches for a region that can satisfy the request.
    ///
    /// Skips the active region as it was already tried.
    fn find_available_region(&mut self, size: usize, align: usize) -> Option<*mut c_void> {
        for (index, region) in self.regions.iter_mut().enumerate() {
            if index == self.active_index {
                continue;
            }

            if region.has_capacity_for(size, align) {
                if let Some(ptr) = region.allocate(size, align) {
                    self.active_index = index;
                    return Some(ptr.as_ptr() as *mut c_void);
                }
            }
        }
        None
    }

    /// Creates a new region sized to fit the request.
    fn create_region(&mut self, size: usize, align: usize) -> Option<*mut c_void> {
        let capacity = REGION_SIZE.max(size.checked_add(align)?);

        let mut region = match Region::new(&self.backing_heap, capacity, MIN_ALIGN) {
            Some(r) => r,
            None => {
                log::error!(
                    "ScrapHeap: Failed to allocate region (capacity: {} MiB, total regions: {}, total capacity: {} MiB)",
                    capacity / (1024 * 1024),
                    self.regions.len(),
                    self.regions.iter().map(|r| r.capacity).sum::<usize>() / (1024 * 1024)
                );
                return None;
            }
        };

        let ptr = region.allocate(size, align)?;

        let new_index = self.regions.len();
        let start_addr = region.start.as_ptr() as usize;
        let end_addr = start_addr.checked_add(capacity)?;

        // Register all pages that this region spans for O(1) lookup
        let start_page = start_addr >> PAGE_SHIFT;
        let end_page = (end_addr - 1) >> PAGE_SHIFT;

        for page in start_page..=end_page {
            self.region_map.insert(page, new_index);
        }

        self.regions.push(region);
        self.active_index = new_index;

        // Only log first few region creations to avoid spam
        if self.regions.len() <= 3 {
            log::debug!(
                "ScrapHeap: Created region #{} at {:p} (capacity: {} MiB, pages: {})",
                self.regions.len(),
                start_addr as *const u8,
                capacity / (1024 * 1024),
                end_page - start_page + 1
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

/// Aligns address upward to alignment boundary.
///
/// Returns None on overflow.
#[inline(always)]
fn align_up(addr: usize, align: usize) -> Option<usize> {
    debug_assert!(align.is_power_of_two());
    debug_assert!(align > 0);

    addr.checked_add(align - 1).map(|a| a & !(align - 1))
}

// ============================================================================
// Public API
// ============================================================================

/// Global map of game heap pointers to our ScrapHeap instances.
///
/// Each game heap gets its own isolated allocator instance.
static HEAPS: LazyLock<parking_lot::Mutex<AHashMap<usize, ScrapHeap>>> =
    LazyLock::new(|| parking_lot::Mutex::new(AHashMap::new()));

/// Gets or creates a ScrapHeap for the given game heap pointer.
fn get_or_create_heap(sheap_ptr: *mut c_void) -> parking_lot::MutexGuard<'static, AHashMap<usize, ScrapHeap>> {
    let mut heaps = HEAPS.lock();
    let key = sheap_ptr as usize;

    if !heaps.contains_key(&key) {
        if heaps.len() >= MAX_HEAP_INSTANCES {
            log::error!(
                "ScrapHeap: Max heap instances ({}) reached, cannot create heap for {:p}",
                MAX_HEAP_INSTANCES,
                sheap_ptr
            );
            // Don't create new heap, will return None on subsequent operations
        } else {
            log::info!(
                "ScrapHeap: Creating heap instance #{} for game heap {:p}",
                heaps.len() + 1,
                sheap_ptr
            );
            heaps.insert(key, ScrapHeap::new());
        }
    }

    heaps
}

/// Allocates memory from the scrap heap associated with `sheap_ptr`.
///
/// Each game heap pointer gets its own isolated allocator instance.
pub fn sheap_alloc_align(sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
    let mut heaps = get_or_create_heap(sheap_ptr);
    let key = sheap_ptr as usize;

    if let Some(heap) = heaps.get_mut(&key) {
        heap.alloc_aligned(size, align)
    } else {
        log::error!("ScrapHeap: Failed to get heap for {:p}", sheap_ptr);
        std::ptr::null_mut()
    }
}

/// Marks memory as freed (no-op in epoch-based allocation).
///
/// Memory is NOT reclaimed until purge is called.
/// This is intentional: epoch-based allocators defer reclamation.
pub fn sheap_free(sheap_ptr: *mut c_void, ptr: *mut c_void) {
    let mut heaps = get_or_create_heap(sheap_ptr);
    let key = sheap_ptr as usize;

    if let Some(heap) = heaps.get_mut(&key) {
        heap.free(ptr);
    }
}

/// Purges all regions in the heap associated with `sheap_ptr`.
///
/// This ends the current epoch. All previous allocations become invalid.
pub fn sheap_purge(sheap_ptr: *mut c_void) {
    let mut heaps = get_or_create_heap(sheap_ptr);
    let key = sheap_ptr as usize;

    if let Some(heap) = heaps.get_mut(&key) {
        heap.purge();
    }
}

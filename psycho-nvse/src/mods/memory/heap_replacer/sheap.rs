//! Scrap heap (sheap) implementation using bump allocators.
//!
//! The game's scrap heap is a fast bump allocator for temporary allocations
//! with batch deallocation. We replace it with bump-scope's Bump allocator
//! and fall back to mimalloc when capacity is exhausted.

use ahash::AHashMap;
use bump_scope::Bump;
use libc::c_void;
use libpsycho::os::windows::winapi::get_current_thread_id;
use parking_lot::Mutex;

/// Allocation header stored before each allocation.
///
/// This header is written immediately before the user data pointer.
/// Memory layout: [AllocationHeader][User Data]
///                       ^                 ^
///                       |                 |
///                  header_ptr        user_ptr (returned to game)
#[repr(C, align(8))]
struct AllocationHeader {
    /// Size of the user allocation (not including header)
    size: usize,
}

/// Size of the allocation header in bytes
const HEADER_SIZE: usize = std::mem::size_of::<AllocationHeader>();

/// Maximum number of blocks
const SHEAP_MAX_BLOCKS: usize = 32;

/// Size of each block in bytes (512KB)
const SHEAP_BUFF_SIZE: usize = 512 * 1024;

/// Total capacity per sheap instance
const SHEAP_CAPACITY_BYTES: usize = SHEAP_MAX_BLOCKS * SHEAP_BUFF_SIZE;// * 2;

/// A single scrap heap instance backed by a bump allocator.
///
/// Uses bump-scope for fast bump allocation with batch deallocation on purge.
/// When the bump allocator is full, falls back to mimalloc for individual allocations.
///
/// # Thread Safety
/// Access is synchronized via RwLock in ScrapHeapManager.
pub(super) struct ScrapHeapInstance {
    sheap_ptr: *mut c_void,
    bump: Option<Bump>,
    thread_id: u32,
    total_allocated: usize,
    total_freed: usize,
    /// Start address of the bump allocator's memory region
    region_start: usize,
    /// End address of the bump allocator's memory region
    region_end: usize,
}

unsafe impl Send for ScrapHeapInstance {}
unsafe impl Sync for ScrapHeapInstance {}

impl ScrapHeapInstance {
    #[inline]
    fn new(sheap_ptr: *mut c_void, thread_id: u32) -> Self {
        let bump = Bump::with_size(SHEAP_CAPACITY_BYTES);
        let (region_start, region_end) = Self::get_bump_region(&bump);

        Self {
            sheap_ptr,
            bump: Some(bump),
            thread_id,
            total_allocated: 0,
            total_freed: 0,
            region_start,
            region_end,
        }
    }

    /// Extracts the memory region (start, end) from a bump allocator.
    #[inline]
    fn get_bump_region(bump: &Bump) -> (usize, usize) {
        let stats = bump.stats();
        let current_chunk = stats.current_chunk();

        let start = current_chunk.chunk_start().as_ptr() as usize;
        let end = current_chunk.chunk_end().as_ptr() as usize;

        (start, end)
    }

    /// Fast check if a pointer falls within this sheap's bump allocator region.
    #[inline(always)]
    pub fn contains_ptr(&self, addr: usize) -> bool {
        addr >= self.region_start && addr < self.region_end
    }

    #[inline(always)]
    fn malloc_aligned(&mut self, size: usize, align: usize) -> *mut c_void {
        // Calculate total size including header
        let total_size = size + HEADER_SIZE;

        // Ensure alignment is at least header alignment (8 bytes)
        let actual_align = align.max(std::mem::align_of::<AllocationHeader>());

        if let Some(bump) = self.bump.as_mut() {
            let layout = match std::alloc::Layout::from_size_align(total_size, actual_align) {
                Ok(layout) => layout,
                Err(_) => {
                    log::error!("Invalid layout: size={}, align={}", total_size, actual_align);
                    return std::ptr::null_mut();
                }
            };

            if let Ok(ptr) = bump.try_alloc_layout(layout) {
                let base_addr = ptr.as_ptr() as usize;

                // Write header at the base address
                let header = AllocationHeader { size };
                unsafe {
                    std::ptr::write(base_addr as *mut AllocationHeader, header);
                }

                // Return pointer after the header (this is what the game sees)
                let user_ptr = (base_addr + HEADER_SIZE) as *mut c_void;

                self.total_allocated += size;

                return user_ptr;
            }

            log::warn!(
                "Sheap {:p} bump allocator exhausted (16MB), switching to mimalloc",
                self.sheap_ptr
            );
            self.bump = None;
        }

        // Fallback to mimalloc - also use header-based allocation
        unsafe {
            let ptr = libmimalloc::mi_malloc_aligned(total_size, actual_align);
            if ptr.is_null() {
                return std::ptr::null_mut();
            }

            // Write header for mimalloc allocation too
            let header = AllocationHeader { size };
            std::ptr::write(ptr as *mut AllocationHeader, header);

            // Return user pointer after header
            (ptr as usize + HEADER_SIZE) as *mut c_void
        }
    }

    #[inline(always)]
    fn free(&mut self, addr: *mut c_void) -> bool {
        if addr.is_null() {
            return false;
        }

        let user_addr = addr as usize;

        // Calculate header address (stored before user data)
        let header_addr = user_addr - HEADER_SIZE;

        // Check if the header is within our bump allocator region
        if !self.contains_ptr(header_addr) {
            // Not in our bump region - might be mimalloc allocation
            // For mimalloc allocations, we free the entire allocation (header + user data)
            unsafe {
                if libmimalloc::mi_is_in_heap_region(header_addr as *const c_void) {
                    // Free the entire allocation (header + user data) via mimalloc
                    libmimalloc::mi_free(header_addr as *mut c_void);
                    return true;
                }
            }

            log::debug!("(free:{:p}) Pointer does not belong to this sheap!", addr);
            return false;
        }

        // Read the allocation header
        let header = unsafe { std::ptr::read(header_addr as *const AllocationHeader) };

        // Update freed counter
        self.total_freed += header.size;

        // Check if we can reset the bump allocator
        let can_reset = self.total_freed >= self.total_allocated;

        if can_reset {
            if let Some(bump) = self.bump.as_mut() {
                bump.reset();
                // Update region after reset
                let (region_start, region_end) = Self::get_bump_region(bump);
                self.region_start = region_start;
                self.region_end = region_end;
            }
            self.total_allocated = 0;
            self.total_freed = 0;

            log::trace!("Sheap {:p} auto-reset successful", self.sheap_ptr);
        }

        true
    }

    #[inline]
    fn purge(&mut self) {
        self.bump = None;
        self.total_allocated = 0;
        self.total_freed = 0;
        self.region_start = 0;
        self.region_end = 0;
    }
}

/// Manages all scrap heap instances.
///
/// Provides thread-safe access to per-sheap bump allocators.
/// Automatically initializes sheaps when first accessed (handles late plugin loading).
pub(super) struct ScrapHeapManager {
    instances: Mutex<AHashMap<usize, ScrapHeapInstance>>,
}

impl ScrapHeapManager {
    #[inline]
    pub fn new() -> Self {
        Self {
            instances: Mutex::new(AHashMap::new()),
        }
    }

    #[inline]
    pub fn init(&self, sheap_ptr: *mut c_void, thread_id: u32) {
        let mut instances = self.instances.lock();
        let key = sheap_ptr as usize;

        if let Some(instance) = instances.get_mut(&key) {
            let bump = Bump::with_size(SHEAP_CAPACITY_BYTES);
            let (region_start, region_end) = ScrapHeapInstance::get_bump_region(&bump);

            instance.bump = Some(bump);
            instance.thread_id = thread_id;
            instance.region_start = region_start;
            instance.region_end = region_end;
            return;
        }

        instances.insert(key, ScrapHeapInstance::new(sheap_ptr, thread_id));
    }

    /// Allocates memory from the specified sheap.
    ///
    /// Auto-initializes unknown sheaps to handle late plugin loading where
    /// the game created sheaps before our hooks were installed.
    #[inline(always)]
    pub fn alloc(&self, sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
        let mut instances = self.instances.lock();
        let key = sheap_ptr as usize;

        if let Some(instance) = instances.get_mut(&key) {
            if instance.bump.is_none() {
                let bump = Bump::with_size(SHEAP_CAPACITY_BYTES);
                let (region_start, region_end) = ScrapHeapInstance::get_bump_region(&bump);

                instance.bump = Some(bump);
                instance.thread_id = get_current_thread_id();
                instance.region_start = region_start;
                instance.region_end = region_end;
            }

            return instance.malloc_aligned(size, align);
        }

        let thread_id = get_current_thread_id();
        let mut new_instance = ScrapHeapInstance::new(sheap_ptr, thread_id);

        let ptr = new_instance.malloc_aligned(size, align);
        instances.insert(key, new_instance);

        ptr
    }

    #[inline(always)]
    pub fn free(&self, sheap_ptr: *mut c_void, addr: *mut c_void) -> bool {
        let mut instances = self.instances.lock();
        let key = sheap_ptr as usize;

        if let Some(instance) = instances.get_mut(&key) {
            return instance.free(addr);
        }

        false
    }

    #[inline]
    pub fn purge(&self, sheap_ptr: *mut c_void) {
        let mut instances = self.instances.lock();
        let key = sheap_ptr as usize;

        if let Some(instance) = instances.get_mut(&key) {
            instance.purge();
        }
    }
}

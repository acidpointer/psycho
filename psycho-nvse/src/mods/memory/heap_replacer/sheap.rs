//! Scrap heap (sheap) implementation using bump allocators.
//!
//! The game's scrap heap is a fast bump allocator for temporary allocations
//! with batch deallocation. We replace it with bump-scope's Bump allocator
//! and fall back to mimalloc when capacity is exhausted.

use ahash::AHashMap;
use bump_scope::Bump;
use libc::c_void;
use libpsycho::os::windows::winapi::get_current_thread_id;
use parking_lot::RwLock;

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
    allocations: AHashMap<usize, usize>,
    total_allocated: usize,
    total_freed: usize,
}

unsafe impl Send for ScrapHeapInstance {}
unsafe impl Sync for ScrapHeapInstance {}

impl ScrapHeapInstance {
    #[inline]
    fn new(sheap_ptr: *mut c_void, thread_id: u32) -> Self {
        Self {
            sheap_ptr,
            bump: Some(Bump::with_size(SHEAP_CAPACITY_BYTES)),
            thread_id,
            allocations: AHashMap::new(),
            total_allocated: 0,
            total_freed: 0,
        }
    }

    #[inline(always)]
    fn malloc_aligned(&mut self, size: usize, align: usize) -> *mut c_void {
        if let Some(bump) = self.bump.as_mut() {
            let layout = match std::alloc::Layout::from_size_align(size, align) {
                Ok(layout) => layout,
                Err(_) => {
                    log::error!("Invalid layout: size={}, align={}", size, align);
                    return std::ptr::null_mut();
                }
            };

            if let Ok(ptr) = bump.try_alloc_layout(layout) {
                let addr = ptr.as_ptr() as usize;
                self.allocations.insert(addr, size);
                self.total_allocated += size;
                return addr as *mut c_void;
            }

            log::warn!(
                "Sheap {:p} bump allocator exhausted (32MB), switching to mimalloc",
                self.sheap_ptr
            );
            self.bump = None;
        }

        unsafe { libmimalloc::mi_malloc_aligned(size, align) }
    }

    #[inline(always)]
    fn free(&mut self, addr: *mut c_void) -> bool {
        let addr_usize = addr as usize;

        if let Some(size) = self.allocations.remove(&addr_usize) {
            self.total_freed += size;

            if self.total_freed >= self.total_allocated {
                if let Some(bump) = self.bump.as_mut() {
                    bump.reset();
                }
                self.allocations.clear();
                self.total_allocated = 0;
                self.total_freed = 0;
            }

            return true;
        }

        false
    }

    #[inline]
    fn purge(&mut self) {
        self.bump = None;
        self.allocations.clear();
        self.total_allocated = 0;
        self.total_freed = 0;
    }
}

/// Manages all scrap heap instances.
///
/// Provides thread-safe access to per-sheap bump allocators.
/// Automatically initializes sheaps when first accessed (handles late plugin loading).
pub(super) struct ScrapHeapManager {
    instances: RwLock<AHashMap<usize, ScrapHeapInstance>>,
}

impl ScrapHeapManager {
    #[inline]
    pub fn new() -> Self {
        Self {
            instances: RwLock::new(AHashMap::new()),
        }
    }

    #[inline]
    pub fn init(&self, sheap_ptr: *mut c_void, thread_id: u32) {
        let mut instances = self.instances.write();
        let key = sheap_ptr as usize;

        if let Some(instance) = instances.get_mut(&key) {
            instance.bump = Some(Bump::with_size(SHEAP_CAPACITY_BYTES));
            instance.thread_id = thread_id;
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
        let mut instances = self.instances.write();
        let key = sheap_ptr as usize;

        if let Some(instance) = instances.get_mut(&key) {
            if instance.bump.is_none() {
                instance.bump = Some(Bump::with_size(SHEAP_CAPACITY_BYTES));
                instance.thread_id = get_current_thread_id();
            }

            return instance.malloc_aligned(size, align);
        }

        let thread_id = get_current_thread_id();
        let new_instance = ScrapHeapInstance::new(sheap_ptr, thread_id);
        instances.insert(key, new_instance);

        instances.get_mut(&key).unwrap().malloc_aligned(size, align)
    }

    #[inline(always)]
    pub fn free(&self, sheap_ptr: *mut c_void, addr: *mut c_void) -> bool {
        let mut instances = self.instances.write();
        let key = sheap_ptr as usize;

        if let Some(instance) = instances.get_mut(&key) {
            return instance.free(addr);
        }

        false
    }

    #[inline]
    pub fn purge(&self, sheap_ptr: *mut c_void) {
        let mut instances = self.instances.write();
        let key = sheap_ptr as usize;

        if let Some(instance) = instances.get_mut(&key) {
            instance.purge();
        } else {
            let thread_id = get_current_thread_id();
            let mut new_instance = ScrapHeapInstance::new(sheap_ptr, thread_id);
            new_instance.purge();
            instances.insert(key, new_instance);
        }
    }
}

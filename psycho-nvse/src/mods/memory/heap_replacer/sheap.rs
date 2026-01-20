//! Scrap heap (sheap) implementation using bump allocators.
//!
//! The game's scrap heap is a fast bump allocator for temporary allocations
//! with batch deallocation. We replace it with bump-scope's Bump allocator
//! and fall back to mimalloc when capacity is exhausted.

use bump_scope::Bump;
use libc::c_void;
use libpsycho::os::windows::winapi::get_current_thread_id;
use parking_lot::RwLock;

/// Maximum number of 512KB blocks in original C++ implementation
const SHEAP_MAX_BLOCKS: usize = 32;

/// Size of each block in bytes (512KB)
const SHEAP_BUFF_SIZE: usize = 512 * 1024;

/// Total capacity per sheap instance (16MB)
const SHEAP_CAPACITY_BYTES: usize = SHEAP_MAX_BLOCKS * SHEAP_BUFF_SIZE;

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
    fallback_count: usize,
}

unsafe impl Send for ScrapHeapInstance {}
unsafe impl Sync for ScrapHeapInstance {}

impl ScrapHeapInstance {
    fn new(sheap_ptr: *mut c_void, thread_id: u32) -> Self {
        Self {
            sheap_ptr,
            bump: Some(Bump::with_size(SHEAP_CAPACITY_BYTES)),
            thread_id,
            fallback_count: 0,
        }
    }

    fn malloc_aligned(&mut self, size: usize, align: usize) -> *mut c_void {
        let bump = match self.bump.as_mut() {
            Some(b) => b,
            None => {
                log::error!(
                    "Allocation attempted on purged sheap {:p}",
                    self.sheap_ptr
                );
                return std::ptr::null_mut();
            }
        };

        let layout = match std::alloc::Layout::from_size_align(size, align) {
            Ok(layout) => layout,
            Err(_) => {
                log::error!("Invalid layout: size={}, align={}", size, align);
                return std::ptr::null_mut();
            }
        };

        match bump.try_alloc_layout(layout) {
            Ok(ptr) => ptr.as_ptr() as *mut c_void,
            Err(_) => {
                self.fallback_count += 1;

                if self.fallback_count == 1 || self.fallback_count % 1000 == 0 {
                    log::warn!(
                        "Bump allocator full for sheap {:p}, fallback count: {}",
                        self.sheap_ptr,
                        self.fallback_count
                    );
                }

                unsafe { libmimalloc::mi_malloc_aligned(size, align) }
            }
        }
    }

    fn purge(&mut self) {
        log::info!(
            "Purging sheap {:p}, fallback count: {}",
            self.sheap_ptr,
            self.fallback_count
        );

        self.bump = None;
        self.fallback_count = 0;
    }
}

/// Manages all scrap heap instances.
///
/// Provides thread-safe access to per-sheap bump allocators.
/// Automatically initializes sheaps when first accessed (handles late plugin loading).
pub(super) struct ScrapHeapManager {
    instances: RwLock<Vec<ScrapHeapInstance>>,
}

impl ScrapHeapManager {
    pub const fn new() -> Self {
        Self {
            instances: RwLock::new(Vec::new()),
        }
    }

    pub fn init(&self, sheap_ptr: *mut c_void, thread_id: u32) {
        let mut instances = self.instances.write();

        if let Some(instance) = instances.iter_mut().find(|inst| inst.sheap_ptr == sheap_ptr) {
            instance.bump = Some(Bump::with_size(SHEAP_CAPACITY_BYTES));
            instance.thread_id = thread_id;
            instance.fallback_count = 0;
            return;
        }

        instances.push(ScrapHeapInstance::new(sheap_ptr, thread_id));
    }

    /// Allocates memory from the specified sheap.
    ///
    /// Auto-initializes unknown sheaps to handle late plugin loading where
    /// the game created sheaps before our hooks were installed.
    pub fn alloc(&self, sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
        let mut instances = self.instances.write();

        if let Some(instance) = instances.iter_mut().find(|inst| inst.sheap_ptr == sheap_ptr) {
            if instance.bump.is_none() {
                instance.bump = Some(Bump::with_size(SHEAP_CAPACITY_BYTES));
                instance.thread_id = get_current_thread_id();
                instance.fallback_count = 0;
            }

            return instance.malloc_aligned(size, align);
        }

        let thread_id = get_current_thread_id();
        instances.push(ScrapHeapInstance::new(sheap_ptr, thread_id));

        if let Some(instance) = instances.iter_mut().find(|inst| inst.sheap_ptr == sheap_ptr) {
            instance.malloc_aligned(size, align)
        } else {
            log::error!("Failed to find just-created sheap instance");
            unsafe { libmimalloc::mi_malloc_aligned(size, align) }
        }
    }

    pub fn purge(&self, sheap_ptr: *mut c_void) {
        let mut instances = self.instances.write();

        if let Some(instance) = instances.iter_mut().find(|inst| inst.sheap_ptr == sheap_ptr) {
            instance.purge();
        } else {
            let thread_id = get_current_thread_id();
            let mut new_instance = ScrapHeapInstance::new(sheap_ptr, thread_id);
            new_instance.purge();
            instances.push(new_instance);
        }
    }
}

use std::{alloc::Layout, cell::RefCell};

use bump_scope::Bump;
use libc::c_void;

/// Header with metadata, which appends to each allocation
///
/// Memory layout:
/// [HEADER][allocated_data]
/// Where `HEADER` is always constant size
#[repr(C)]
pub struct SheapMetaHeader {
    ptr: *mut c_void,
    real_ptr: *mut c_void,
    size: usize,
    real_size: usize,
    sheap_ptr: *mut c_void,
    generation: u64,
}

/// Size of allocation header
const SHEAP_HEADER_SIZE: usize = size_of::<SheapMetaHeader>();

/// Total size of scrap heap instance
const SHEAP_SIZE: usize = 16 * 1024 * 1024; // 16 mb

/// Instance of scrap heap.
///
/// It is small re-usable heap with constant size.
pub struct SheapInstance {
    bump: Bump,
    sheap_ptr: *mut c_void,

    allocated: usize,
    freed: usize,
    is_purged: bool,
    generation: u64,
}

impl SheapInstance {
    pub fn new(sheap_ptr: *mut c_void) -> Self {
        let bump = Bump::with_size(SHEAP_SIZE);

        Self {
            sheap_ptr,
            bump,
            allocated: 0,
            freed: 0,
            is_purged: false,
            generation: 0,
        }
    }

    /// Returns region of currently used chunk in initialized bump.
    #[inline]
    fn get_bump_region(&self) -> (usize, usize) {
        let stats = self.bump.stats();
        let current_chunk = stats.current_chunk();

        let start = current_chunk.chunk_start().as_ptr() as usize;
        let end = current_chunk.chunk_end().as_ptr() as usize;

        (start, end)
    }

    #[inline]
    pub fn is_our_ptr(&self, ptr: *mut c_void) -> bool {
        // After purge, no valid memory exists
        if self.is_purged {
            return false;
        }

        let (region_start, region_end) = self.get_bump_region();

        let addr = ptr as usize;

        // Check if pointer is in our memory region
        if !(addr >= region_start && addr < region_end) {
            return false;
        }

        // Read header to check generation
        let header_ptr = ptr.wrapping_sub(SHEAP_HEADER_SIZE) as *mut SheapMetaHeader;
        let header = unsafe { std::ptr::read(header_ptr) };

        // Pointer belongs to us only if generation matches
        header.generation == self.generation
    }

    /// Restore instance after purge, preparing it for new allocations
    #[inline(always)]
    pub fn restore_after_purge(&mut self) {
        // Instance was purged, now being reused - clear the flag
        self.is_purged = false;
        // Generation was already incremented during purge
        // Allocated and freed counters were already reset to 0
    }

    #[inline(always)]
    pub fn malloc_aligned(&mut self, sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
        let actual_align = align.max(std::mem::align_of::<SheapMetaHeader>());

        // Allocate extra space: header + alignment padding + size
        // This ensures header always fits before aligned user address
        let real_size = size + SHEAP_HEADER_SIZE + actual_align;

        let alloc_layout = Layout::from_size_align(real_size, actual_align)
            .inspect_err(|err| {
                log::error!(
                    "sheap::malloc_aligned({}, {}) failed with error: {:?}",
                    size,
                    align,
                    err
                )
            })
            .unwrap();

        let base_ptr = self.bump.alloc_layout(alloc_layout).as_ptr() as usize;

        // Calculate aligned user address
        let min_user_addr = base_ptr + SHEAP_HEADER_SIZE;
        let user_addr = (min_user_addr + actual_align - 1) & !(actual_align - 1);

        // Header must be immediately before user data
        let header_addr = user_addr - SHEAP_HEADER_SIZE;

        // Safety check: ensure header fits within allocated region
        // This should never fail due to allocation size, but check anyway
        if header_addr < base_ptr {
            log::error!(
                "CRITICAL: Header underflow! base={:#x}, header={:#x}, user={:#x}, size={}, align={}",
                base_ptr,
                header_addr,
                user_addr,
                size,
                align
            );

            panic!("Sheap header underflow!");
        }

        let header = SheapMetaHeader {
            size,
            real_size,
            ptr: user_addr as *mut c_void,
            real_ptr: base_ptr as *mut c_void,
            sheap_ptr,
            generation: self.generation,
        };

        unsafe {
            std::ptr::write(header_addr as *mut SheapMetaHeader, header);
        }

        self.allocated += real_size;

        user_addr as *mut c_void
    }

    /// Internal method to perform the actual purge operation
    #[inline(always)]
    fn do_purge(&mut self) {
        self.bump.reset();
        self.freed = 0;
        self.allocated = 0;
        self.is_purged = true;
        self.generation += 1;
    }

    #[inline(always)]
    pub fn free(&mut self, ptr: *mut c_void) -> bool {
        // is_our_ptr now checks generation and purged flag
        if !self.is_our_ptr(ptr) {
            return false;
        }

        let header_ptr = ptr.wrapping_sub(SHEAP_HEADER_SIZE) as *mut SheapMetaHeader;
        let header = unsafe { std::ptr::read(header_ptr) };

        self.freed += header.real_size;

        // Automatic purge if all memory freed (game engine has purge call bugs)
        if self.freed == self.allocated {
            log::debug!("Auto-purge triggered: all memory freed (allocated={}, freed={})", self.allocated, self.freed);
            self.do_purge();
        }

        true
    }

    #[inline(always)]
    pub fn purge(&mut self, _sheap_ptr: *mut c_void) {
        self.do_purge();
    }

    #[inline(always)]
    pub fn is_can_alloc(&self, size: usize) -> bool {
        // After purge, instance is completely available
        if self.is_purged {
            return size + SHEAP_HEADER_SIZE <= SHEAP_SIZE;
        }

        let used = self.allocated.saturating_sub(self.freed);
        SHEAP_SIZE.saturating_sub(used) >= size + SHEAP_HEADER_SIZE
    }
}

thread_local! {
    static SHEAP_INSTANCES: RefCell<Vec<SheapInstance>> = const { RefCell::new(vec![]) };
}

pub struct Sheap;

impl Sheap {
    pub fn malloc_aligned(sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
        SHEAP_INSTANCES.with(|sheaps| {
            let mut sheaps_vec = sheaps.borrow_mut();

            // Find an instance for this exact sheap_ptr with available space
            for sheap in sheaps_vec.iter_mut() {
                if sheap.sheap_ptr == sheap_ptr && sheap.is_can_alloc(size) {
                    // Restore instance if it was purged
                    if sheap.is_purged {
                        sheap.restore_after_purge();
                    }
                    return sheap.malloc_aligned(sheap_ptr, size, align);
                }
            }

            // No matching instance with space - create new one
            log::debug!("Creating new SHEAP instance for sheap_ptr={:p}", sheap_ptr);

            let mut sheap_instance = SheapInstance::new(sheap_ptr);

            let result = sheap_instance.malloc_aligned(sheap_ptr, size, align);

            sheaps_vec.push(sheap_instance);

            log::debug!(
                "New SHEAP instance added for {:p}. Total instances: {}",
                sheap_ptr,
                sheaps_vec.len()
            );

            result
        })
    }

    pub fn free(_sheap_ptr: *mut c_void, ptr: *mut c_void) {
        SHEAP_INSTANCES.with(|sheaps| {
            let mut sheaps_vec = sheaps.borrow_mut();

            for sheap in sheaps_vec.iter_mut() {
                if sheap.free(ptr) {
                    return;
                }
            }
        })
    }

    pub fn purge(sheap_ptr: *mut c_void) {
        SHEAP_INSTANCES.with(|sheaps| {
            let mut sheaps_vec = sheaps.borrow_mut();

            let mut purged_count = 0;

            // Only purge instances that belong to this sheap_ptr
            for sheap in sheaps_vec.iter_mut() {
                if sheap.sheap_ptr == sheap_ptr {
                    sheap.purge(sheap_ptr);
                    purged_count += 1;
                }
            }

            log::debug!(
                "sheap_purge called for sheap_ptr={:p}, purged {} instances",
                sheap_ptr,
                purged_count
            );
        })
    }
}

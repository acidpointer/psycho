use libc::c_void;
use parking_lot::Mutex;
use std::alloc::Layout;
use std::mem::{size_of, align_of};

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
    is_valid: bool,
    sheap_addr: usize,
    magic: u32,
}

/// Size of allocation header
const SHEAP_HEADER_SIZE: usize = size_of::<SheapMetaHeader>();

/// Align of allocation header
const SHEAP_HEADER_ALIGN: usize = align_of::<SheapMetaHeader>();

/// Total size of scrap heap instance
const SHEAP_SIZE: usize = 2 * 1024 * 1024; // 2 Mb per block

const SHEAP_MAGIC: u32 = 0x53484550; // 'SHEP' in hex

/// Instance of scrap heap.
///
/// It is small re-usable heap with constant size.
pub struct SheapInstance {
    //bump: Bump,
    base_ptr: *mut c_void,
    current_ptr: *mut c_void,
    layout: Layout,
    allocated: usize,
    freed: usize,
    active_allocs: usize,
    sheap_addr: usize,
}

unsafe impl Send for SheapInstance {}
unsafe impl Sync for SheapInstance {}

impl Drop for SheapInstance {
    fn drop(&mut self) {
        unsafe {
            std::alloc::dealloc(self.base_ptr as *mut u8, self.layout);
        }
    }
}

impl SheapInstance {
    pub fn try_new(sheap_ptr: *mut c_void) -> Option<Self> {
        match std::alloc::Layout::from_size_align(SHEAP_SIZE, SHEAP_HEADER_ALIGN) {
            Ok(layout) => {
                let ptr = unsafe { std::alloc::alloc(layout) };

                if !ptr.is_null() {
                    Some(Self {
                        base_ptr: ptr as *mut c_void,
                        current_ptr: ptr as *mut c_void,
                        allocated: 0,
                        active_allocs: 0,
                        freed: 0,
                        sheap_addr: sheap_ptr as usize,
                        layout,
                    })
                } else {
                    log::error!(
                        "(SHEAP:{:p}) Sheap allocation failed with NULLPTR",
                        sheap_ptr
                    );
                    None
                }
            }

            Err(err) => {
                log::error!("(SHEAP:{:p}) Sheap allocation failed: {:?}", sheap_ptr, err);
                None
            }
        }
    }

    #[inline(always)]
    pub fn malloc_aligned(
        &mut self,
        sheap_ptr: *mut c_void,
        size: usize,
        align: usize,
    ) -> Option<*mut c_void> {
        let actual_align = align.max(SHEAP_HEADER_ALIGN);

        // Calculate the earliest possible user data address
        // It must be at least SHEAP_HEADER_SIZE bytes after current_ptr
        let min_user_addr = (self.current_ptr as usize).checked_add(SHEAP_HEADER_SIZE)?;

        // Align THAT address to satisfy the game's alignment requirement
        let aligned_user_addr = (min_user_addr + actual_align - 1) & !(actual_align - 1);

        // The header MUST be placed exactly SHEAP_HEADER_SIZE before the aligned user address
        // This ensures read_header (ptr - SHEAP_HEADER_SIZE) always hits the struct
        let header_addr = aligned_user_addr - SHEAP_HEADER_SIZE;

        // Calculate where this allocation ends
        let final_current_ptr = aligned_user_addr.checked_add(size)?;

        // Boundary check
        let base_addr = self.base_ptr as usize;
        if final_current_ptr > base_addr.checked_add(SHEAP_SIZE)? {
            log::error!(
                "(SHEAP:{:X}) Allocation would exceed heap bounds (Size: {}, Align: {})",
                self.sheap_addr,
                size,
                align
            );
            return None;
        }

        // Calculate actual size used (including the padding we just created)
        let actual_size_used = final_current_ptr - (self.current_ptr as usize);

        let header = SheapMetaHeader {
            size,
            real_size: actual_size_used,
            ptr: aligned_user_addr as *mut c_void,
            real_ptr: self.current_ptr, // We store the actual start of the bump segment
            is_valid: true,
            sheap_addr: sheap_ptr as usize,
            magic: SHEAP_MAGIC,
        };

        // Write the header to its calculated position
        unsafe {
            std::ptr::write(header_addr as *mut SheapMetaHeader, header);
        }

        // Update stats and bump pointer
        self.allocated = self.allocated.checked_add(actual_size_used)?;
        self.active_allocs = self.active_allocs.checked_add(1)?;
        self.current_ptr = final_current_ptr as *mut c_void;

        Some(aligned_user_addr as *mut c_void)
    }

    #[inline(always)]
    pub fn purge(&mut self, sheap_ptr: *mut c_void) -> bool {
        if sheap_ptr as usize != self.sheap_addr {
            return false;
        }

        // Reset the bump allocator by returning to the base pointer
        self.current_ptr = self.base_ptr;
        self.freed = 0;
        self.allocated = 0;
        self.active_allocs = 0;

        true
    }

    #[inline(always)]
    pub fn free(&mut self, sheap_ptr: *mut c_void, ptr: *mut c_void) -> bool {
        if self.active_allocs == 0 || ptr.is_null() {
            return false;
        }

        let addr = ptr as usize;
        let heap_start = self.base_ptr as usize;
        let heap_end = heap_start + SHEAP_SIZE;

        if addr < (heap_start + SHEAP_HEADER_SIZE) || addr >= heap_end {
            // Not in this specific instance's memory range
            return false;
        }

        // Locate Header (Sticky positioning)
        let header_ptr = (addr - SHEAP_HEADER_SIZE) as *mut SheapMetaHeader;

        // Safety check: Ensure header_ptr is aligned to SheapMetaHeader requirements
        if !(header_ptr as usize).is_multiple_of(SHEAP_HEADER_ALIGN) {
            log::debug!(
                "(SHEAP) Rejecting unaligned header pointer: {:p}",
                header_ptr
            );
            return false;
        }

        let header = unsafe { std::ptr::read(header_ptr) };

        // If the magic doesn't match, this is a serious logic error or
        // the pointer wasn't allocated by our Sheap system.
        if header.magic != SHEAP_MAGIC {
            return false;
        }

        if !header.is_valid || header.sheap_addr != self.sheap_addr {
            return false;
        }

        self.freed += header.real_size;
        self.active_allocs -= 1;

        // Invalidate the Header
        // We wipe the magic and is_valid flag so we don't double-free
        let cleared_header = SheapMetaHeader {
            ptr: std::ptr::null_mut(),
            real_ptr: std::ptr::null_mut(),
            size: 0,
            real_size: 0,
            is_valid: false,
            sheap_addr: 0,
            magic: 0, // Clear magic!
        };
        unsafe { std::ptr::write(header_ptr, cleared_header) };

        // Auto-Purge Logic
        // If this was the last active allocation, or if the math says we've
        // freed everything we allocated, reset the bump pointer to the start.
        // if self.active_allocs == 0 || self.freed >= self.allocated {
        //     self.purge(sheap_ptr);
        // }

        true
    }

    #[inline(always)]
    pub fn is_can_alloc(&self, sheap_ptr: *mut c_void, size: usize, align: usize) -> bool {
        if sheap_ptr as usize != self.sheap_addr {
            return false;
        }

        let actual_align = align.max(SHEAP_HEADER_ALIGN);
        let max_padding = if actual_align > 0 {
            actual_align - 1
        } else {
            0
        };

        // Check for potential overflow in size calculations
        let total_size_needed = match size.checked_add(SHEAP_HEADER_SIZE) {
            Some(val) => val,
            None => return false,
        };
        let total_size_needed = match total_size_needed.checked_add(max_padding) {
            Some(val) => val,
            None => return false,
        };

        // Check if we have enough space left in the heap
        let current_offset = self.current_ptr as usize - self.base_ptr as usize;
        let remaining_space = match SHEAP_SIZE.checked_sub(current_offset) {
            Some(val) => val,
            None => return false,
        };

        remaining_space >= total_size_needed
    }
}

static POOL: Mutex<Vec<SheapInstance>> = const { Mutex::new(vec![]) };

pub struct Sheap;

impl Sheap {
    fn with_pool<T: Copy, F: Fn(&mut Vec<SheapInstance>) -> T>(callback: F) -> T {
        let mut pool = POOL.lock();

        callback(&mut pool)
    }

    pub fn malloc_aligned(sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
        Self::with_pool(|pool| {
            for sheap in pool.iter_mut() {
                if sheap.is_can_alloc(sheap_ptr, size, align)
                    && let Some(ptr) = sheap.malloc_aligned(sheap_ptr, size, align)
                {
                    return ptr;
                }
            }

            // If no existing sheap can allocate, try to create a new one
            if let Some(mut sheap_instance) = SheapInstance::try_new(sheap_ptr) {
                if let Some(ptr) = sheap_instance.malloc_aligned(sheap_ptr, size, align) {
                    pool.push(sheap_instance);
                    return ptr;
                } else {
                    log::error!(
                        "Newly created sheap {:p} failed to allocate memory first time! Discarding instance.",
                        sheap_ptr
                    );
                }
            }

            let mut total_pool_active = 0;
            let mut total_pool_allocated = 0;
            let mut total_pool_freed = 0;
            for sheap in pool.iter() {
                total_pool_active += sheap.active_allocs;
                total_pool_allocated += sheap.allocated;
                total_pool_freed += sheap.freed;
            }

            log::warn!("STATISTICS:");
            log::warn!("Total allocated in pool: {} bytes", total_pool_allocated);
            log::warn!("Total active allocations: {}", total_pool_active);
            log::warn!("Total freed by pool: {}", total_pool_freed);

            std::ptr::null_mut()
        })
    }

    pub fn free(sheap_ptr: *mut c_void, ptr: *mut c_void) {
        if ptr.is_null() {
            return;
        }

        if sheap_ptr.is_null() {
            return;
        }

        Self::with_pool(|pool| {
            for (index, sheap) in pool.iter_mut().enumerate() {
                if sheap.free(sheap_ptr, ptr) {
                    if sheap.active_allocs == 0 {
                        pool.swap_remove(index);
                    }
                    return;
                }
            }

            log::debug!(
                "[SHEAP] Pointer {:p} was not found in any active pool instance",
                ptr
            );
        });
    }

    pub fn purge(sheap_ptr: *mut c_void) {
        Self::with_pool(|pool| {
            for (index, sheap) in pool.iter_mut().enumerate() {
                if sheap.purge(sheap_ptr) {
                    pool.swap_remove(index);
                    return;
                }
            }
        })
    }
}

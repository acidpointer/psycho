use std::alloc::Layout;
use std::mem::size_of;
use libc::c_void;
use parking_lot::Mutex;

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
const SHEAP_HEADER_ALIGN: usize = std::mem::align_of::<SheapMetaHeader>();

/// Total size of scrap heap instance
const SHEAP_SIZE: usize = 8 * 1024 * 1024; // 8 mb per block

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

    /// SAFETY: ptr must point to valid allocation with header
    #[inline(always)]
    fn read_header(ptr: *mut c_void) -> SheapMetaHeader {
        // Verify that the pointer has space for a header before it
        let ptr_addr = ptr as usize;
        if ptr_addr < SHEAP_HEADER_SIZE {
            // Return a default invalid header instead of panicking
            return SheapMetaHeader {
                ptr: std::ptr::null_mut(),
                real_ptr: std::ptr::null_mut(),
                size: 0,
                real_size: 0,
                is_valid: false,
                sheap_addr: 0,
                magic: 0,
            };
        }

        let header_ptr = (ptr as usize - SHEAP_HEADER_SIZE) as *const SheapMetaHeader;
        unsafe { std::ptr::read(header_ptr) }
    }

    /// SAFETY: must have space for header before ptr
    #[inline(always)]
    fn write_header(ptr: *mut c_void, header: SheapMetaHeader) {
        // Verify that the pointer has space for a header before it
        let ptr_addr = ptr as usize;
        if ptr_addr < SHEAP_HEADER_SIZE {
            // Log error but don't panic to avoid crashing the game
            log::error!("Attempted to write header to invalid address: {:p}", ptr);
            return;
        }

        let header_ptr = (ptr as usize - SHEAP_HEADER_SIZE) as *mut SheapMetaHeader;
        unsafe { std::ptr::write(header_ptr, header) }
    }

    #[inline(always)]
    fn check_ptr_and_get_header(&self, ptr: *mut c_void) -> Option<SheapMetaHeader> {
        if ptr.is_null() {
            return None;
        }

        // Basic address validation to prevent obvious wild pointers
        let addr = ptr as usize;
        if !(0x10000..=0x7FFF0000).contains(&addr) {
            // More conservative upper bound
            return None;
        }

        // Validate that the address is within our heap's range
        let heap_start = self.base_ptr as usize;
        let heap_end = heap_start + SHEAP_SIZE;
        if addr < heap_start || addr >= heap_end {
            return None;
        }

        // Also validate that there's space for a header before this address
        if addr < SHEAP_HEADER_SIZE {
            return None;
        }

        let header = Self::read_header(ptr);

        // If it's not our magic, it's not our pointer. Instant return.
        if header.magic != SHEAP_MAGIC || !header.is_valid || header.sheap_addr != self.sheap_addr {
            return None;
        }

        // Validate that the size values make sense
        if header.size > SHEAP_SIZE || header.real_size > SHEAP_SIZE {
            return None;
        }

        // Additional validation: check if the stored real_ptr points to a reasonable location
        // (should be near the user data pointer)
        let real_ptr_addr = header.real_ptr as usize;
        let user_ptr_addr = ptr as usize;
        if real_ptr_addr != user_ptr_addr - SHEAP_HEADER_SIZE {
            return None; // The real_ptr should point to the header location
        }

        Some(header)
    }

    #[inline(always)]
    pub fn malloc_aligned(
        &mut self,
        sheap_ptr: *mut c_void,
        size: usize,
        align: usize,
    ) -> Option<*mut c_void> {
        let actual_align = align.max(SHEAP_HEADER_ALIGN);

        // Check for potential overflow in size calculations
        let max_padding = if actual_align > 0 {
            actual_align - 1
        } else {
            0
        };
        let total_size_needed = size
            .checked_add(SHEAP_HEADER_SIZE)?
            .checked_add(max_padding)?;

        // Check if we have enough space left in the heap
        let current_offset = self.current_ptr as usize - self.base_ptr as usize;
        let space_remaining = SHEAP_SIZE.checked_sub(current_offset)?;
        if total_size_needed > space_remaining {
            log::error!(
                "(SHEAP:{:X}) Not enough space for allocation of size {}, align {}",
                self.sheap_addr,
                size,
                align
            );
            return None;
        }

        // Calculate aligned user address
        let potential_user_addr = (self.current_ptr as usize).checked_add(SHEAP_HEADER_SIZE)?;
        let aligned_user_addr = (potential_user_addr + actual_align - 1) & !(actual_align - 1);

        // Calculate where the final pointer will be
        let final_current_ptr = aligned_user_addr.checked_add(size)?;

        // Verify that the calculated addresses are within bounds
        let base_addr = self.base_ptr as usize;
        if final_current_ptr > base_addr.checked_add(SHEAP_SIZE)? {
            log::error!(
                "(SHEAP:{:X}) Allocation would exceed heap bounds",
                self.sheap_addr
            );
            return None;
        }

        // Calculate the actual size used including padding due to alignment
        let actual_start = self.current_ptr as usize;
        let actual_end = final_current_ptr;
        let actual_size_used = actual_end - actual_start;

        let header = SheapMetaHeader {
            size,
            real_size: actual_size_used,
            ptr: aligned_user_addr as *mut c_void,
            real_ptr: (aligned_user_addr - SHEAP_HEADER_SIZE) as *mut c_void, // Point to the header location
            is_valid: true,
            sheap_addr: sheap_ptr as usize,
            magic: SHEAP_MAGIC,
        };

        Self::write_header(aligned_user_addr as *mut c_void, header);

        // Update statistics with overflow checking
        self.allocated = self.allocated.checked_add(actual_size_used)?;
        self.active_allocs = self.active_allocs.checked_add(1)?;

        // Update current_ptr after successful allocation
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
        if self.active_allocs == 0 {
            return false;
        }

        if ptr.is_null() {
            return false;
        }

        let Some(header) = self.check_ptr_and_get_header(ptr) else {
            return false;
        };

        // Additional safety check: make sure the header size is reasonable
        if header.size == 0 || header.real_size == 0 {
            log::error!("Invalid header size detected for pointer {:p}", ptr);
            return false;
        }

        // Check for integer overflow in freed counter
        if self.freed.checked_add(header.real_size).is_none() {
            log::error!(
                "Integer overflow in freed counter for sheap {:p}",
                sheap_ptr
            );
            return false;
        }

        self.freed += header.real_size;
        self.active_allocs -= 1;

        // Clear header to invalidate this pointer
        let cleared_header = SheapMetaHeader {
            ptr: std::ptr::null_mut(),
            real_ptr: std::ptr::null_mut(),
            size: 0,
            real_size: 0,
            is_valid: false,
            sheap_addr: 0,
            magic: SHEAP_MAGIC,
        };
        Self::write_header(ptr, cleared_header);

        // Auto-purge if it was last allocation
        if self.active_allocs == 0 {
            self.purge(sheap_ptr);
        }

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
            None => return false, // This shouldn't happen in normal circumstances
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

    /// Clean up empty sheap instances to prevent pool growth
    fn cleanup_pool() {
        // Only hold the lock briefly to get the indices to remove
        let indices_to_remove: Vec<usize> = {
            let pool = POOL.lock();
            pool.iter()
                .enumerate()
                .filter(|(_, instance)| instance.active_allocs == 0)
                .map(|(idx, _)| idx)
                .collect()
        };

        // Remove the instances (in reverse order to maintain indices)
        if !indices_to_remove.is_empty() {
            let mut pool = POOL.lock();
            for &idx in indices_to_remove.iter().rev() {
                if idx < pool.len() {
                    pool.remove(idx);
                }
            }
        }
    }

    pub fn malloc_aligned(sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
        Self::with_pool(|pool| {
            // First, try to allocate from existing sheaps
            for sheap in pool.iter_mut() {
                if sheap.is_can_alloc(sheap_ptr, size, align)
                    && let Some(ptr) = sheap.malloc_aligned(sheap_ptr, size, align) {
                        return ptr;
                    }
            }

            // If no existing sheap can allocate, try to create a new one
            if let Some(mut sheap_instance) = SheapInstance::try_new(sheap_ptr) {
                if let Some(ptr) = sheap_instance.malloc_aligned(sheap_ptr, size, align) {
                    pool.push(sheap_instance);
                    return ptr;
                } else {
                    // If the new instance can't allocate immediately, don't add it to the pool
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
        Self::with_pool(|pool| {
            // Check if the pointer is null before proceeding
            if ptr.is_null() {
                return;
            }

            for (index, sheap) in pool.iter_mut().enumerate() {
                // Make sure the sheap belongs to the correct parent sheap
                if sheap.sheap_addr == sheap_ptr as usize
                    && sheap.free(sheap_ptr, ptr) {
                        // Clean-up after auto purge
                        if sheap.active_allocs == 0 {
                            pool.swap_remove(index);
                        }
                        return;
                    }
            }
            // If we reach here, the pointer wasn't found in any sheap instance
            // This can happen if the sheap was already purged but there are lingering references
            // Don't log this as it can cause spam as seen in the bug report
        });

        // Trigger cleanup more proactively when the pool grows large
        // Use a static counter to avoid overhead
        use std::sync::atomic::{AtomicUsize, Ordering};
        static FREE_COUNTER: AtomicUsize = AtomicUsize::new(0);

        let count = FREE_COUNTER.fetch_add(1, Ordering::Relaxed);
        // Cleanup every 1000 frees if pool is large (more frequent than before)
        if count.is_multiple_of(1000) {
            // Check pool size under lock to avoid race condition
            let pool_len = POOL.lock().len();
            if pool_len > 5 {  // Lower threshold (was 10)
                // Only cleanup if we have many instances
                Self::cleanup_pool();
            }
        }
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

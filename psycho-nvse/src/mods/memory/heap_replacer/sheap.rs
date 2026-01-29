use std::alloc::Layout;

use bump_scope::Bump;
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
}

/// Size of allocation header
const SHEAP_HEADER_SIZE: usize = size_of::<SheapMetaHeader>();

/// Align of allocation header
const SHEAP_HEADER_ALIGN: usize = std::mem::align_of::<SheapMetaHeader>();

/// Total size of scrap heap instance
const SHEAP_SIZE: usize = 16 * 1024 * 1024; // 16 mb per block

/// Instance of scrap heap.
///
/// It is small re-usable heap with constant size.
pub struct SheapInstance {
    bump: Bump,
    allocated: usize,
    freed: usize,
    active_allocs: usize,
    region_start: usize,
    sheap_addr: usize,
}

impl SheapInstance {
    pub fn new(sheap_ptr: *mut c_void) -> Self {
        let bump = Bump::with_size(SHEAP_SIZE);

        let stats: bump_scope::stats::Stats<'_> = bump.stats();

        let region_start = stats.current_chunk().chunk_start().as_ptr() as usize;
        Self {
            bump,
            allocated: 0,
            freed: 0,
            active_allocs: 0,
            region_start,
            sheap_addr: sheap_ptr as usize,
        }
    }

    /// SAFETY: ptr must point to valid allocation with header
    #[inline(always)]
    fn read_header(ptr: *mut c_void) -> SheapMetaHeader {
        let header_ptr = ptr.wrapping_sub(SHEAP_HEADER_SIZE) as *const SheapMetaHeader;
        unsafe { std::ptr::read(header_ptr) }
    }

    /// SAFETY: must have space for header before ptr
    #[inline(always)]
    fn write_header(ptr: *mut c_void, header: SheapMetaHeader) {
        let header_ptr = ptr.wrapping_sub(SHEAP_HEADER_SIZE) as *mut SheapMetaHeader;
        unsafe { std::ptr::write(header_ptr, header) }
    }

    #[inline]
    fn get_bump_region(&self) -> (usize, usize) {
        let stats = self.bump.stats();
        let chunk = stats.current_chunk();
        let region_end = chunk.chunk_end().as_ptr() as usize;
        (self.region_start, region_end)
    }

    #[inline]
    fn check_ptr_and_get_header(&self, ptr: *mut c_void) -> Option<SheapMetaHeader> {
        let (region_start, region_end) = self.get_bump_region();
        let addr = ptr as usize;

        if !(addr >= region_start && addr < region_end) {
            return None;
        }

        let header = Self::read_header(ptr);

        if header.is_valid && header.sheap_addr == self.sheap_addr {
            Some(header)
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn malloc_aligned(
        &mut self,
        sheap_ptr: *mut c_void,
        size: usize,
        align: usize,
    ) -> Option<*mut c_void> {
        if sheap_ptr as usize != self.sheap_addr {
            return None;
        }

        let actual_align = align.max(SHEAP_HEADER_ALIGN);
        let real_size = size + SHEAP_HEADER_SIZE + actual_align;

        let alloc_layout = Layout::from_size_align(real_size, actual_align)
            .inspect_err(|err| log::error!("malloc_aligned failed: {:?}", err))
            .unwrap();

        let base_ptr = self.bump.alloc_layout(alloc_layout).as_ptr() as usize;
        let min_user_addr = base_ptr + SHEAP_HEADER_SIZE;
        let user_addr = (min_user_addr + actual_align - 1) & !(actual_align - 1);
        let header_addr = user_addr - SHEAP_HEADER_SIZE;

        if header_addr < base_ptr {
            log::error!(
                "(SHEAP:{:X})  header underflow! Returning NONE and try again in next block",
                self.sheap_addr
            );
            return None;
        }

        let header = SheapMetaHeader {
            size,
            real_size,
            ptr: user_addr as *mut c_void,
            real_ptr: base_ptr as *mut c_void,
            is_valid: true,
            sheap_addr: self.sheap_addr,
        };

        Self::write_header(user_addr as *mut c_void, header);
        self.allocated += real_size;
        self.active_allocs += 1;

        Some(user_addr as *mut c_void)
    }

    #[inline(always)]
    pub fn purge(&mut self, sheap_ptr: *mut c_void) -> bool {
        if sheap_ptr as usize != self.sheap_addr {
            return false;
        }

        self.bump.reset();
        self.freed = 0;
        self.allocated = 0;
        self.active_allocs = 0;

        // Update region bounds after reset
        let stats = self.bump.stats();
        self.region_start = stats.current_chunk().chunk_start().as_ptr() as usize;

        true
    }

    #[inline(always)]
    pub fn free(&mut self, sheap_ptr: *mut c_void, ptr: *mut c_void) -> bool {
        if sheap_ptr as usize != self.sheap_addr {
            return false;
        }

        let Some(header) = self.check_ptr_and_get_header(ptr) else {
            return false;
        };

        // Double-free protection
        if self.freed + header.real_size > self.allocated {
            return true;
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
        };
        Self::write_header(ptr, cleared_header);

        // Auto-purge when all memory freed
        // if self.active_allocs == 0 {
        //     log::debug!(
        //         "(SHEAP:{:X}) Auto-purge: allocated={}, freed={}",
        //         self.sheap_addr,
        //         self.allocated,
        //         self.freed
        //     );
        //     self.purge(sheap_ptr);
        // }

        true
    }

    #[inline(always)]
    pub fn is_can_alloc(&self, sheap_ptr: *mut c_void, size: usize, align: usize) -> bool {
        if sheap_ptr as usize != self.sheap_addr {
            return false;
        }

        let header_and_padding = SHEAP_HEADER_SIZE + align + 32; // Overestimate padding
        let total_requested = size + header_and_padding;

        let stats = self.bump.stats();
        let remaining = stats.remaining();

        remaining >= total_requested
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
                if sheap.is_can_alloc(sheap_ptr, size, align) {
                    match sheap.malloc_aligned(sheap_ptr, size, align) {
                        Some(ptr) => return ptr,
                        None => continue,
                    }
                } else if sheap.active_allocs == 0 && sheap.allocated == 0 {
                    log::info!("Reusing idle instance for new sheap {:p}", sheap_ptr);
                    sheap.sheap_addr = sheap_ptr as usize;
                    // Region bounds are already correct from last purge
                    match sheap.malloc_aligned(sheap_ptr, size, align) {
                        Some(ptr) => return ptr,
                        None => continue,
                    }
                }
            }

/*             log::warn!(
                "New sheap instance will be created for sheap: {:p}. Current amount: {}",
                sheap_ptr,
                pool.len(),
            ); */

            let mut sheap_instance = SheapInstance::new(sheap_ptr);
            match sheap_instance.malloc_aligned(sheap_ptr, size, align) {
                Some(ptr) => {
                    pool.push(sheap_instance);
                    ptr
                }
                None => {
                    log::error!(
                        "Newly created sheap {:p} failed to allocate memory first time! Returning NULLPTR",
                        sheap_ptr
                    );

                    std::ptr::null_mut()
                }
            }
        })
    }

    pub fn free(sheap_ptr: *mut c_void, ptr: *mut c_void) {
        Self::with_pool(|pool| {
            for sheap in pool.iter_mut() {
                if sheap.free(sheap_ptr, ptr) {
                    return;
                }
            }
        })
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

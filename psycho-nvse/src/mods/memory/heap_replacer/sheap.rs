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
    is_valid: bool,
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
}

impl SheapInstance {
    pub fn new(sheap_ptr: *mut c_void) -> Self {
        Self {
            sheap_ptr,
            bump: Bump::with_size(SHEAP_SIZE),
            allocated: 0,
            freed: 0,
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
        let start = chunk.chunk_start().as_ptr() as usize;
        let end = chunk.chunk_end().as_ptr() as usize;
        (start, end)
    }

    #[inline]
    fn check_ptr_and_get_header(&self, ptr: *mut c_void) -> Option<SheapMetaHeader> {
        let (region_start, region_end) = self.get_bump_region();
        let addr = ptr as usize;

        if !(addr >= region_start && addr < region_end) {
            return None;
        }

        let header = Self::read_header(ptr);

        if header.is_valid {
            Some(header)
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn malloc_aligned(&mut self, sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
        let actual_align = align.max(std::mem::align_of::<SheapMetaHeader>());
        let real_size = size + SHEAP_HEADER_SIZE + actual_align;

        let alloc_layout = Layout::from_size_align(real_size, actual_align)
            .inspect_err(|err| log::error!("malloc_aligned failed: {:?}", err))
            .unwrap();

        let base_ptr = self.bump.alloc_layout(alloc_layout).as_ptr() as usize;
        let min_user_addr = base_ptr + SHEAP_HEADER_SIZE;
        let user_addr = (min_user_addr + actual_align - 1) & !(actual_align - 1);
        let header_addr = user_addr - SHEAP_HEADER_SIZE;

        if header_addr < base_ptr {
            panic!("Sheap header underflow!");
        }

        let header = SheapMetaHeader {
            size,
            real_size,
            ptr: user_addr as *mut c_void,
            real_ptr: base_ptr as *mut c_void,
            sheap_ptr,
            is_valid: true,
        };

        Self::write_header(user_addr as *mut c_void, header);
        self.allocated += real_size;

        user_addr as *mut c_void
    }

    #[inline(always)]
    fn purge(&mut self) {
        self.bump.reset();
        self.freed = 0;
        self.allocated = 0;
    }

    #[inline(always)]
    pub fn free(&mut self, ptr: *mut c_void) -> bool {
        let Some(header) = self.check_ptr_and_get_header(ptr) else {
            return false;
        };

        // Double-free protection
        if self.freed + header.real_size > self.allocated {
            return true;
        }

        self.freed += header.real_size;

        // Clear header to invalidate this pointer
        let cleared_header = SheapMetaHeader {
            ptr: std::ptr::null_mut(),
            real_ptr: std::ptr::null_mut(),
            size: 0,
            real_size: 0,
            sheap_ptr: std::ptr::null_mut(),
            is_valid: false,
        };
        Self::write_header(ptr, cleared_header);

        // Auto-purge when all memory freed
        if self.freed == self.allocated {
            log::debug!("Auto-purge: allocated={}, freed={}", self.allocated, self.freed);
            self.purge();
        }

        true
    }

    #[inline(always)]
    pub fn is_can_alloc(&self, size: usize) -> bool {
        const MAX_ALIGN: usize = 64;
        let needed = size + SHEAP_HEADER_SIZE + MAX_ALIGN + (MAX_ALIGN - 1);

        // Use our tracking, not bump stats (bump may not reset stats on reset())
        let available = SHEAP_SIZE.saturating_sub(self.allocated);

        available >= needed
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

            for sheap in sheaps_vec.iter_mut() {
                if sheap.is_can_alloc(size) {
                    sheap.sheap_ptr = sheap_ptr;
                    return sheap.malloc_aligned(sheap_ptr, size, align);
                }
            }

            log::debug!("Creating SHEAP instance for {:p}", sheap_ptr);

            let mut sheap_instance = SheapInstance::new(sheap_ptr);
            let result = sheap_instance.malloc_aligned(sheap_ptr, size, align);
            sheaps_vec.push(sheap_instance);

            log::debug!("SHEAP instance created for {:p}, total: {}", sheap_ptr, sheaps_vec.len());

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
}

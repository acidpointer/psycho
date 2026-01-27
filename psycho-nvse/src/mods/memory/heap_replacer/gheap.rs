use std::sync::LazyLock;

use libc::c_void;
use libmimalloc::heap::MiHeap;

#[repr(C)]
struct GheapMetaHeader {
    size: usize,
    base_ptr: *mut c_void,
}

const GHEAP_HEADER_SIZE: usize = size_of::<GheapMetaHeader>();
const GHEAP_HEADER_ALIGN: usize = align_of::<GheapMetaHeader>();
static GAME_HEAP: LazyLock<MiHeap> = LazyLock::new(MiHeap::new);

pub struct Gheap;

impl Gheap {
    #[inline(always)]
    pub fn malloc(size: usize) -> *mut c_void {
        if size == 0 {
            return std::ptr::null_mut();
        }

        let total_size = size + GHEAP_HEADER_SIZE + GHEAP_HEADER_ALIGN;

        let base_ptr = GAME_HEAP.malloc_aligned(total_size, GHEAP_HEADER_ALIGN);

        // If we get NULLPTR, we have some critical shit.
        // Let's return to original call
        if base_ptr.is_null() {
            log::error!("gheap::malloc(): MiHeap::malloc() returned NULLPTR!");
            return std::ptr::null_mut();
        }

        let min_user_addr = base_ptr as usize + GHEAP_HEADER_SIZE;
        let user_addr = (min_user_addr + GHEAP_HEADER_ALIGN - 1) & !(GHEAP_HEADER_ALIGN - 1);
        let header_addr = user_addr - GHEAP_HEADER_SIZE;

        let header = GheapMetaHeader {
            size,
            base_ptr,
        };

        unsafe {
            std::ptr::write(header_addr as *mut GheapMetaHeader, header);
        }

        user_addr as *mut c_void
    }

    #[inline(always)]
    pub fn free(ptr: *mut c_void) {
        if ptr.is_null() {
            return;
        }

        let header_ptr = ptr.wrapping_sub(GHEAP_HEADER_SIZE) as *mut GheapMetaHeader;
        let header = unsafe { std::ptr::read(header_ptr) };

        unsafe {
            libmimalloc::mi_free(header.base_ptr);
        }
    }

    #[inline(always)]
    pub fn realloc(ptr: *mut c_void, new_size: usize) -> *mut c_void {
        if ptr.is_null() {
            return Self::malloc(new_size);
        }

        if new_size == 0 {
            Self::free(ptr);
            return std::ptr::null_mut();
        }

        let user_addr = ptr as usize;
        if user_addr < GHEAP_HEADER_SIZE {
            return std::ptr::null_mut();
        }

        let header_ptr = ptr.wrapping_sub(GHEAP_HEADER_SIZE) as *mut GheapMetaHeader;
        let header = unsafe { std::ptr::read(header_ptr) };

        let new_ptr = Self::malloc(new_size);

        if !new_ptr.is_null() {
            let copy_size = header.size.min(new_size);
            unsafe {
                std::ptr::copy_nonoverlapping(ptr as *const u8, new_ptr as *mut u8, copy_size);
            }
            Self::free(ptr);
        }

        new_ptr
    }

    #[inline(always)]
    pub fn msize(ptr: *mut c_void) -> usize {
        if ptr.is_null() {
            return 0;
        }

        let user_addr = ptr as usize;
        if user_addr < GHEAP_HEADER_SIZE {
            return 0;
        }

        let header_ptr = ptr.wrapping_sub(GHEAP_HEADER_SIZE) as *mut GheapMetaHeader;
        let header = unsafe { std::ptr::read(header_ptr) };

        header.size
    }
}

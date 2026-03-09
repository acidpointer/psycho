use std::sync::LazyLock;

use libc::c_void;

use super::runtime::Runtime;

static RT: LazyLock<Runtime> = LazyLock::new(Runtime::new);

pub struct RegionAllocator;

impl RegionAllocator {
    #[inline(always)]
    pub fn alloc_align(sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
        RT.alloc(sheap_ptr, size, align)
    }

    #[inline(always)]
    pub fn free(sheap_ptr: *mut c_void, ptr: *mut c_void) {
        //RT.free(sheap_ptr, ptr);
    }

    #[inline(always)]
    pub fn purge(sheap_ptr: *mut c_void) {
        RT.purge(sheap_ptr);
    }
}

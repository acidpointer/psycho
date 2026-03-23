//! Lock-free bump-pointer region for the scrap heap allocator.

use libc::c_void;
use std::{
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::mods::memory::heap_replacer::mem_stats;

#[inline(always)]
fn checked_align_up(addr: usize, align: usize) -> Option<usize> {
    let mask = align.wrapping_sub(1);
    addr.checked_add(mask).map(|v| v & !mask)
}

pub struct Region {
    start: NonNull<u8>,
    capacity: usize,
    offset: AtomicUsize,
}

unsafe impl Send for Region {}
unsafe impl Sync for Region {}

impl Region {
    pub fn new(capacity: usize, align: usize) -> Option<Self> {
        let ptr = unsafe { libmimalloc::mi_malloc_aligned(capacity, align) };
        let start = NonNull::new(ptr as *mut u8)?;

        mem_stats::global().sbm2_add(capacity as u64);

        Some(Self {
            start,
            capacity,
            offset: AtomicUsize::new(0),
        })
    }

    /// Lock-free bump-pointer allocation via CAS loop.
    #[inline]
    pub fn allocate(&self, size: usize, align: usize) -> Option<NonNull<c_void>> {
        let start_addr = self.start.as_ptr() as usize;
        let end_addr = start_addr + self.capacity;

        loop {
            let old_offset = self.offset.load(Ordering::Relaxed);

            let min_data_addr = start_addr.checked_add(old_offset)?.checked_add(4)?;
            let data_addr = checked_align_up(min_data_addr, align)?;

            let alloc_end = data_addr.checked_add(size)?;
            if alloc_end > end_addr {
                return None;
            }

            let new_offset = alloc_end - start_addr;

            if self
                .offset
                .compare_exchange_weak(old_offset, new_offset, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                let header_addr = data_addr - 4;
                unsafe {
                    (header_addr as *mut u32).write(size as u32);
                }
                return NonNull::new(data_addr as *mut c_void);
            }
        }
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        unsafe {
            libmimalloc::mi_free(self.start.as_ptr() as *mut c_void);
        }
        mem_stats::global().sbm2_sub(self.capacity as u64);
    }
}

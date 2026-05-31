//! Lock-free bump-pointer region for the scrap heap allocator.

use libc::c_void;
use std::{
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering},
};

use super::super::mem_stats;

use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
};

const PAGE_SIZE: usize = 0x1000;

#[derive(Clone, Copy)]
enum RegionBacking {
    Mimalloc,
    VirtualAlloc,
}

static VIRTUALALLOC_FALLBACKS: AtomicUsize = AtomicUsize::new(0);

#[inline(always)]
fn checked_align_up(addr: usize, align: usize) -> Option<usize> {
    let mask = align.wrapping_sub(1);
    addr.checked_add(mask).map(|v| v & !mask)
}

pub struct Region {
    start: NonNull<u8>,
    capacity: usize,
    offset: AtomicUsize,
    backing: RegionBacking,
    accounted: bool,
}

unsafe impl Send for Region {}
unsafe impl Sync for Region {}

impl Region {
    pub fn new(capacity: usize, align: usize) -> Option<Self> {
        let capacity = checked_align_up(capacity, PAGE_SIZE)?;
        let ptr = unsafe { libmimalloc::mi_malloc_aligned(capacity, align) };
        if let Some(start) = NonNull::new(ptr as *mut u8) {
            mem_stats::global().scrap_heap_add(capacity as u64);
            return Some(Self {
                start,
                capacity,
                offset: AtomicUsize::new(0),
                backing: RegionBacking::Mimalloc,
                accounted: true,
            });
        }

        let region = Self::new_virtual(capacity, true);
        if region.is_some() {
            let n = VIRTUALALLOC_FALLBACKS.fetch_add(1, Ordering::Relaxed) + 1;
            if n.is_power_of_two() {
                log::warn!(
                    "[scrap_heap] region fallback: mimalloc failed, VirtualAlloc succeeded (count={}, capacity={}KB)",
                    n,
                    capacity / 1024,
                );
            }
        }
        region
    }

    pub fn new_emergency(capacity: usize) -> Option<Self> {
        let capacity = checked_align_up(capacity, PAGE_SIZE)?;
        Self::new_virtual(capacity, false)
    }

    fn new_virtual(capacity: usize, accounted: bool) -> Option<Self> {
        let ptr = unsafe { VirtualAlloc(None, capacity, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };
        let start = NonNull::new(ptr as *mut u8)?;

        if accounted {
            mem_stats::global().scrap_heap_add(capacity as u64);
        }

        Some(Self {
            start,
            capacity,
            offset: AtomicUsize::new(0),
            backing: RegionBacking::VirtualAlloc,
            accounted,
        })
    }

    pub fn activate_accounting(&mut self) {
        if self.accounted {
            return;
        }

        mem_stats::global().scrap_heap_add(self.capacity as u64);
        self.accounted = true;
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
        match self.backing {
            RegionBacking::Mimalloc => unsafe {
                libmimalloc::mi_free(self.start.as_ptr() as *mut c_void);
            },
            RegionBacking::VirtualAlloc => {
                if let Err(e) =
                    unsafe { VirtualFree(self.start.as_ptr() as *mut c_void, 0, MEM_RELEASE) }
                {
                    log::error!(
                        "[scrap_heap] VirtualFree failed: base=0x{:08x} capacity={}KB err={:?}",
                        self.start.as_ptr() as usize,
                        self.capacity / 1024,
                        e,
                    );
                }
            }
        }

        if self.accounted {
            mem_stats::global().scrap_heap_sub(self.capacity as u64);
        }
    }
}

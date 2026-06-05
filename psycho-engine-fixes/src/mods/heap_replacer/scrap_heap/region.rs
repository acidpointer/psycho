//! Bump-pointer region for the scrap heap allocator.

use libc::c_void;
use std::{
    mem::size_of,
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering},
};

use super::super::mem_stats;

use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
};

const PAGE_SIZE: usize = 0x1000;
const HEADER_FREED: u32 = 0x8000_0000;

#[repr(C)]
pub struct AllocationHeader {
    size: u32,
    prev: *mut AllocationHeader,
}

const _: () = assert!(size_of::<AllocationHeader>() == 8);
pub const ALLOCATION_HEADER_SIZE: usize = size_of::<AllocationHeader>();

pub struct Allocation {
    pub ptr: NonNull<c_void>,
    pub header: *mut AllocationHeader,
}

#[derive(Clone, Copy)]
enum RegionBacking {
    Mimalloc,
    VirtualAlloc,
}

static VIRTUALALLOC_FALLBACKS: AtomicUsize = AtomicUsize::new(0);

#[inline(always)]
fn checked_align_up(addr: usize, align: usize) -> Option<usize> {
    if align <= 1 {
        return Some(addr);
    }

    let mask = align.wrapping_sub(1);
    addr.checked_add(mask).map(|v| v & !mask)
}

impl AllocationHeader {
    #[inline(always)]
    pub unsafe fn from_payload(ptr: *mut c_void) -> *mut Self {
        unsafe { (ptr as *mut u8).sub(ALLOCATION_HEADER_SIZE) as *mut Self }
    }

    #[inline(always)]
    pub unsafe fn is_freed(header: *mut Self) -> bool {
        unsafe { (*header).size & HEADER_FREED != 0 }
    }

    #[inline(always)]
    pub unsafe fn mark_freed(header: *mut Self) -> bool {
        let size = unsafe { (*header).size };
        if size & HEADER_FREED != 0 {
            return false;
        }

        unsafe {
            (*header).size = size | HEADER_FREED;
        }
        true
    }

    #[inline(always)]
    pub unsafe fn payload_size(header: *mut Self) -> usize {
        unsafe { ((*header).size & !HEADER_FREED) as usize }
    }

    #[inline(always)]
    pub unsafe fn previous(header: *mut Self) -> *mut Self {
        unsafe { (*header).prev }
    }
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

    #[inline]
    pub fn allocate(
        &self,
        size: usize,
        align: usize,
        prev: *mut AllocationHeader,
    ) -> Option<Allocation> {
        if size > (!HEADER_FREED) as usize {
            return None;
        }

        let start_addr = self.start.as_ptr() as usize;
        let end_addr = start_addr + self.capacity;

        let old_offset = self.offset.load(Ordering::Relaxed);
        let min_data_addr = start_addr
            .checked_add(old_offset)?
            .checked_add(ALLOCATION_HEADER_SIZE)?;
        let data_addr = checked_align_up(min_data_addr, align)?;
        let header_addr = data_addr.checked_sub(ALLOCATION_HEADER_SIZE)?;

        let alloc_end = data_addr.checked_add(size)?;
        if alloc_end > end_addr {
            return None;
        }

        let new_offset = alloc_end - start_addr;
        self.offset.store(new_offset, Ordering::Relaxed);

        let header = header_addr as *mut AllocationHeader;
        unsafe {
            header.write(AllocationHeader {
                size: size as u32,
                prev,
            });
        }

        Some(Allocation {
            ptr: NonNull::new(data_addr as *mut c_void)?,
            header,
        })
    }

    #[inline]
    pub fn contains_header(&self, header: *mut AllocationHeader) -> bool {
        let start_addr = self.start.as_ptr() as usize;
        let header_addr = header as usize;
        let Some(header_end) = header_addr.checked_add(ALLOCATION_HEADER_SIZE) else {
            return false;
        };
        let end_addr = start_addr + self.capacity;

        start_addr <= header_addr && header_end <= end_addr
    }

    #[inline]
    pub unsafe fn rewind_after(&self, header: *mut AllocationHeader) -> bool {
        if !self.contains_header(header) {
            return false;
        }

        let start_addr = self.start.as_ptr() as usize;
        let Some(payload_addr) = (header as usize).checked_add(ALLOCATION_HEADER_SIZE) else {
            return false;
        };
        let Some(alloc_end) =
            payload_addr.checked_add(unsafe { AllocationHeader::payload_size(header) })
        else {
            return false;
        };
        let end_addr = start_addr + self.capacity;
        if alloc_end > end_addr {
            return false;
        }

        self.offset.store(alloc_end - start_addr, Ordering::Relaxed);
        true
    }

    #[inline]
    pub fn reset(&self) {
        self.offset.store(0, Ordering::Relaxed);
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

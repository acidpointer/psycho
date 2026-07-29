//! Bump-pointer storage for one ScrapHeap identity.
//!
//! A region is either a standard 128 KiB slot leased from the protected
//! reserve or an exact, page-rounded `VirtualAlloc` mapping used after reserve
//! exhaustion and for oversized requests. The backing enum keeps those
//! ownership rules explicit: dropping a [`ReservedSlot`] returns reserved
//! storage, while dynamic storage is released directly.
//!
//! Allocations carry an eight-byte header immediately before the aligned
//! payload. Headers form a per-heap reverse chain used to skip already freed
//! tail allocations and rewind the bump pointer. Individual payloads are not
//! returned to the OS; an empty heap releases whole regions during purge.
//!
//! `Region::allocate`, `reset`, and `rewind_after` are serialized by the
//! owning heap's state mutex. Their atomic offset permits shared references
//! across the published region pointer, but does not make concurrent bump
//! allocation valid by itself.

use libc::c_void;
use std::{
    mem::size_of,
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering},
};

use super::super::mem_stats;
use super::reserve::ReservedSlot;

use libpsycho::os::windows::winapi::{virtual_release, virtual_reserve_commit};

const PAGE_SIZE: usize = 0x1000;
const HEADER_FREED: u32 = 0x8000_0000;

/// Header stored immediately before each returned ScrapHeap payload.
///
/// The high bit of `size` is the internal freed marker. Payload sizes larger
/// than the remaining 31 bits are rejected.
#[repr(C)]
pub struct AllocationHeader {
    size: u32,
    prev: *mut AllocationHeader,
}

const _: [(); 8] = [(); size_of::<AllocationHeader>()];
/// Bytes reserved immediately before every returned payload.
pub const ALLOCATION_HEADER_SIZE: usize = size_of::<AllocationHeader>();

/// Successful region allocation returned to the owning heap.
pub struct Allocation {
    /// Aligned payload pointer returned to the engine.
    pub ptr: NonNull<c_void>,
    /// Header linked into the owning heap's allocation chain.
    pub header: *mut AllocationHeader,
}

enum RegionBacking {
    // Keeping the lease in the enum ties mapping ownership to Region lifetime.
    Reserved { _lease: ReservedSlot },
    DynamicVirtualAlloc,
}

static DYNAMIC_LIVE: AtomicUsize = AtomicUsize::new(0);
static DYNAMIC_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

#[inline(always)]
fn checked_align_up(addr: usize, align: usize) -> Option<usize> {
    if align <= 1 {
        return Some(addr);
    }

    let mask = align.wrapping_sub(1);
    addr.checked_add(mask).map(|v| v & !mask)
}

impl AllocationHeader {
    /// Recover the header address immediately preceding a returned payload.
    ///
    /// # Safety
    ///
    /// `ptr` must be a payload returned by this allocator and must still refer
    /// to a live region.
    #[inline(always)]
    pub unsafe fn from_payload(ptr: *mut c_void) -> *mut Self {
        unsafe { (ptr as *mut u8).sub(ALLOCATION_HEADER_SIZE) as *mut Self }
    }

    /// Return whether the header has already been marked free.
    ///
    /// # Safety
    ///
    /// `header` must point to an initialized, readable allocation header.
    #[inline(always)]
    pub unsafe fn is_freed(header: *mut Self) -> bool {
        unsafe { (*header).size & HEADER_FREED != 0 }
    }

    /// Atomically-with-respect-to-the-heap-lock mark a header free.
    ///
    /// Returns `false` for a duplicate free. The bit update itself is not an
    /// atomic CPU operation; callers must hold the owning heap's state mutex.
    ///
    /// # Safety
    ///
    /// `header` must point to an initialized, writable allocation header.
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

    /// Read the payload size without the internal freed marker.
    ///
    /// # Safety
    ///
    /// `header` must point to an initialized, readable allocation header.
    #[inline(always)]
    pub unsafe fn payload_size(header: *mut Self) -> usize {
        unsafe { ((*header).size & !HEADER_FREED) as usize }
    }

    /// Read the preceding header in the owning heap's reverse chain.
    ///
    /// # Safety
    ///
    /// `header` must point to an initialized, readable allocation header.
    #[inline(always)]
    pub unsafe fn previous(header: *mut Self) -> *mut Self {
        unsafe { (*header).prev }
    }
}

/// Fixed-address bump allocator with explicit backing ownership.
///
/// A `Region` must remain boxed after publication because [`Heap`](super::heap::Heap)
/// caches its address. The owning heap is responsible for serializing all
/// mutating methods.
pub struct Region {
    start: NonNull<u8>,
    capacity: usize,
    offset: AtomicUsize,
    backing: RegionBacking,
}

// The raw address and header links refer only to the region's own backing.
// HeapState serializes every allocation, rewind, reset, and destruction before
// a Region can cross threads. The atomic offset allows the published shared
// reference but is not used as a lock-free allocator.
unsafe impl Send for Region {}
unsafe impl Sync for Region {}

impl Region {
    /// Build a standard region that owns one protected-reserve lease.
    pub fn from_reserved(slot: ReservedSlot) -> Self {
        mem_stats::global().scrap_heap_add(super::heap::REGION_SIZE as u64);
        Self {
            start: slot.start(),
            capacity: super::heap::REGION_SIZE,
            offset: AtomicUsize::new(0),
            backing: RegionBacking::Reserved { _lease: slot },
        }
    }

    /// Allocate an exact dynamic mapping rounded up to a host page.
    ///
    /// Dynamic backing preserves coverage for oversized requests and for
    /// standard requests that arrive while every reserve slot is leased.
    /// Returns `None` on arithmetic overflow or `VirtualAlloc` failure.
    pub fn new_dynamic(capacity: usize) -> Option<Self> {
        let capacity = checked_align_up(capacity, PAGE_SIZE)?;
        let ptr = unsafe { virtual_reserve_commit(None, capacity) };
        let start = NonNull::new(ptr as *mut u8)?;
        mem_stats::global().scrap_heap_add(capacity as u64);
        DYNAMIC_LIVE.fetch_add(1, Ordering::Relaxed);
        DYNAMIC_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);

        Some(Self {
            start,
            capacity,
            offset: AtomicUsize::new(0),
            backing: RegionBacking::DynamicVirtualAlloc,
        })
    }

    /// Return whether this region is backed by the protected reserve.
    #[cfg(test)]
    pub fn is_reserved(&self) -> bool {
        matches!(&self.backing, RegionBacking::Reserved { .. })
    }

    /// Allocate one payload and link its header to `prev`.
    ///
    /// The owning heap must serialize calls. `align` follows the engine hook's
    /// existing power-of-two alignment contract.
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

        // The heap mutex makes this load/store pair a serialized bump update;
        // using fetch_add would not handle alignment and would imply unsupported
        // lock-free allocation semantics.
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

    /// Return whether the complete header lies inside this region.
    ///
    /// This proves range ownership only. Callers still rely on the engine hook
    /// contract that a freed pointer is the exact payload start returned by
    /// this heap.
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

    /// Rewind the bump offset to the end of a validated live allocation.
    ///
    /// Returns `false` if the header or its encoded payload size escapes the
    /// region.
    ///
    /// # Safety
    ///
    /// `header` must name an initialized allocation header owned by this
    /// region, and the owning heap must serialize the call.
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

    /// Reset an empty region to its first byte.
    ///
    /// The owning heap must have proved that no live allocation refers to the
    /// region and must serialize this call.
    #[inline]
    pub fn reset(&self) {
        self.offset.store(0, Ordering::Relaxed);
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        match &self.backing {
            RegionBacking::Reserved { .. } => {}
            RegionBacking::DynamicVirtualAlloc => {
                DYNAMIC_LIVE.fetch_sub(1, Ordering::Relaxed);
                if let Err(e) = unsafe { virtual_release(self.start.as_ptr() as *mut c_void) } {
                    log::error!(
                        "[scrap_heap] VirtualFree failed: base=0x{:08x} capacity={}KB err={:?}",
                        self.start.as_ptr() as usize,
                        self.capacity / 1024,
                        e,
                    );
                }
            }
        }

        mem_stats::global().scrap_heap_sub(self.capacity as u64);
    }
}

/// Return the number of dynamic region mappings currently owned by heaps.
pub fn dynamic_live() -> usize {
    DYNAMIC_LIVE.load(Ordering::Relaxed)
}

/// Return the cumulative number of successful dynamic region mappings.
pub fn dynamic_allocations() -> usize {
    DYNAMIC_ALLOCATIONS.load(Ordering::Relaxed)
}

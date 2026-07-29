//! Per-identity ScrapHeap allocation state.
//!
//! Fallout exposes multiple ScrapHeap identities, including thread-local
//! instances. Each identity owns a [`Heap`] whose mutex serializes region
//! selection, bump allocation, header-chain updates, free, and purge.
//! `hot_region` is an atomic address hint that avoids rescanning older regions;
//! it is not a lock-free allocation path.
//!
//! Free marks the allocation header and rewinds only through a contiguous
//! freed tail. Regions remain owned and readable until the live-allocation
//! count reaches zero. The last free queues the identity for collection, and
//! [`Heap::checked_purge`] rechecks the count under the state mutex before
//! releasing any backing. This delayed, checked transition is the boundary
//! that prevents a queued identity from purging allocations created later.

use super::region::{ALLOCATION_HEADER_SIZE, AllocationHeader, Region};
use super::runtime::SeqQueue;

use crossfire::flavor::Queue;
use libc::c_void;
use parking_lot::Mutex;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

/// Capacity of one standard region and one protected-reserve slot.
///
/// A fresh mapping of this size can still fail in a fragmented 32-bit process;
/// the reusable reserve exists specifically to avoid that mapping dependency.
pub const REGION_SIZE: usize = 128 * 1024;

const CACHE_LINE: usize = 64;

struct HeapState {
    // `hot_region` publishes Region addresses independently of Vec storage.
    // Boxing keeps those addresses stable when this Vec grows or compacts.
    #[allow(clippy::vec_box)]
    pool: Vec<Box<Region>>,
    top: *mut AllocationHeader,
}

// `top` is accessed only while `state` is locked, and every pointed-to header
// remains inside one of the boxed regions owned by the same state.
unsafe impl Send for HeapState {}

/// Scrap heap allocator for a single sheap identity.
///
/// The object has a stable address because the runtime retains its `Arc` for
/// process lifetime. That permits thread-local lookup entries to cache a raw
/// pointer; `generation` invalidates cached allocator state after purge.
#[repr(C, align(64))]
pub struct Heap {
    // === Cache line 1: read-heavy ===
    hot_region: AtomicPtr<Region>,
    generation: AtomicUsize,
    _pad_read: [u8; CACHE_LINE - 2 * size_of::<usize>()],

    // === Cache line 2: RMW-heavy ===
    alloc_count: AtomicUsize,
    _pad_write: [u8; CACHE_LINE - size_of::<usize>()],

    // === Cache line 3+: cold ===
    state: Mutex<HeapState>,
    gc_queued: AtomicBool,
    gc_queue: Arc<SeqQueue<usize>>,
    sheap_id: usize,
}

impl Heap {
    /// Create an empty allocator for one native ScrapHeap identity.
    pub fn new(sheap_id: usize, gc_queue: Arc<SeqQueue<usize>>) -> Self {
        Self {
            hot_region: AtomicPtr::new(ptr::null_mut()),
            generation: AtomicUsize::new(0),
            _pad_read: [0; CACHE_LINE - 2 * size_of::<usize>()],
            alloc_count: AtomicUsize::new(0),
            _pad_write: [0; CACHE_LINE - size_of::<usize>()],
            state: Mutex::new(HeapState {
                pool: Vec::with_capacity(8),
                top: ptr::null_mut(),
            }),
            gc_queued: AtomicBool::new(false),
            gc_queue,
            sheap_id,
        }
    }

    /// Return the purge generation used to validate thread-local cache entries.
    #[inline(always)]
    pub fn get_generation(&self) -> usize {
        self.generation.load(Ordering::Acquire)
    }

    /// Allocate from existing storage or request one new region from `provider`.
    ///
    /// `provider` is called only after every existing region has been tried and
    /// while the heap state mutex remains held. Holding the lock across region
    /// acquisition prevents two threads from adding redundant regions or
    /// publishing competing header-chain tops for the same identity.
    pub fn try_alloc_slow_with_provider<F>(
        &self,
        size: usize,
        align: usize,
        region_provider: F,
    ) -> Option<*mut c_void>
    where
        F: FnOnce(usize) -> Option<Box<Region>>,
    {
        let mut state = self.state.lock();

        if let Some(ptr) = self.try_alloc_existing(&mut state, size, align) {
            return Some(ptr);
        }

        let min_capacity = size
            .checked_add(align)?
            .checked_add(ALLOCATION_HEADER_SIZE)?;
        let region_capacity = REGION_SIZE.max(min_capacity);
        // The provider owns reserve/dynamic policy. Keeping that policy out of
        // Heap lets this type enforce lifetime and header invariants without
        // knowing how a region obtained its backing.
        let boxed = region_provider(region_capacity)?;

        let allocation = boxed.allocate(size, align, state.top)?;
        let ptr = allocation.ptr;
        state.top = allocation.header;
        self.publish_region(&boxed);
        state.pool.push(boxed);

        self.alloc_count.fetch_add(1, Ordering::Relaxed);
        Some(ptr.as_ptr())
    }

    fn try_alloc_existing(
        &self,
        state: &mut HeapState,
        size: usize,
        align: usize,
    ) -> Option<*mut c_void> {
        let start_index = self.alloc_start_index(state);

        for index in start_index..state.pool.len() {
            let region = &state.pool[index];
            if let Some(allocation) = region.allocate(size, align, state.top) {
                state.top = allocation.header;
                self.publish_region(region);
                self.alloc_count.fetch_add(1, Ordering::Relaxed);
                return Some(allocation.ptr.as_ptr());
            }
        }

        None
    }

    fn alloc_start_index(&self, state: &HeapState) -> usize {
        if state.pool.is_empty() {
            return 0;
        }

        let hot = self.hot_region.load(Ordering::Acquire);
        if !hot.is_null()
            && let Some(index) = self.region_index_by_ptr(state, hot)
        {
            return index;
        }

        if !state.top.is_null()
            && let Some(index) = self.region_index_for_header(state, state.top)
        {
            return index;
        }

        0
    }

    #[inline]
    fn publish_region(&self, region: &Region) {
        self.hot_region
            .store(region as *const Region as *mut Region, Ordering::Release);
    }

    #[inline]
    fn dec_alloc_count(&self) -> bool {
        loop {
            let current = self.alloc_count.load(Ordering::Acquire);
            if current == 0 {
                log::error!(
                    "[scrap_heap] alloc_count underflow on heap_id={:#x}",
                    self.sheap_id
                );
                return false;
            }

            match self.alloc_count.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return current == 1,
                Err(_) => continue,
            }
        }
    }

    /// Free an exact payload pointer returned by this heap.
    ///
    /// Foreign pointers are rejected by region-range ownership. A duplicate
    /// free is ignored after observing the header marker. The exact-start
    /// requirement comes from the native ScrapHeap ABI and is not inferred
    /// from range membership.
    #[inline]
    pub fn free(&self, ptr: *mut c_void) {
        let should_enqueue_gc = {
            let mut state = self.state.lock();
            let header = unsafe { AllocationHeader::from_payload(ptr) };
            if self.region_index_for_header(&state, header).is_none() {
                log::error!(
                    "[scrap_heap] free for foreign pointer: heap_id={:#x} ptr={:#x}",
                    self.sheap_id,
                    ptr as usize,
                );
                return;
            }

            if !unsafe { AllocationHeader::mark_freed(header) } {
                return;
            }

            let should_enqueue_gc = self.dec_alloc_count();
            self.rewind_after_free(&mut state);
            should_enqueue_gc
        };

        if should_enqueue_gc {
            // Queueing is only a hint that the heap became empty. A later
            // allocation may make it live again before the collector runs, so
            // checked_purge must prove zero again under the same state lock.
            self.try_enqueue_gc();
        }
    }

    #[inline]
    fn try_enqueue_gc(&self) {
        if self.gc_queued.swap(true, Ordering::AcqRel) {
            return;
        }

        if let Err(failed_id) = self.gc_queue.push(self.sheap_id) {
            log::error!(
                "[scrap_heap] GC queue push failed for heap_id={:#x}",
                failed_id
            );
            self.gc_queued.store(false, Ordering::Release);
        }
    }

    /// Purge every owned region without checking the live-allocation count.
    ///
    /// Native explicit purge/init hooks call this only at an engine-owned
    /// lifetime boundary where all previous allocations are invalid.
    /// Returns the number of regions released.
    #[inline]
    pub fn purge(&self) -> usize {
        let mut state = self.state.lock();
        self.purge_inner(&mut state)
    }

    /// Purge queued storage only if the heap is still empty.
    ///
    /// The zero-live check occurs while holding the state mutex, closing the
    /// race between the last-free enqueue and a later allocation. Returns the
    /// number of regions released, or zero if the identity became live again.
    #[inline]
    pub fn checked_purge(&self) -> usize {
        self.gc_queued.store(false, Ordering::Release);

        let mut state = self.state.lock();

        if self.alloc_count.load(Ordering::Acquire) != 0 {
            self.publish_current_region(&state);
            return 0;
        }

        self.purge_inner(&mut state)
    }

    fn purge_inner(&self, state: &mut HeapState) -> usize {
        self.hot_region.store(ptr::null_mut(), Ordering::Release);

        let old_len = state.pool.len();
        state.pool.clear();
        state.top = ptr::null_mut();

        self.alloc_count.store(0, Ordering::Release);
        self.gc_queued.store(false, Ordering::Release);
        // Cached Heap pointers stay valid because the runtime never removes
        // identities. The generation change nevertheless forces thread-local
        // users to cross the slow validation path after allocator state reset.
        self.generation.fetch_add(1, Ordering::Release);

        old_len
    }

    /// Return the number of region objects currently owned by this heap.
    pub fn region_count(&self) -> usize {
        self.state.lock().pool.len()
    }

    /// Return the current number of live allocations in this heap.
    pub fn alloc_count(&self) -> usize {
        self.alloc_count.load(Ordering::Relaxed)
    }

    /// Return the native ScrapHeap identity represented by this object.
    pub fn identity(&self) -> usize {
        self.sheap_id
    }

    fn rewind_after_free(&self, state: &mut HeapState) {
        while !state.top.is_null() && unsafe { AllocationHeader::is_freed(state.top) } {
            state.top = unsafe { AllocationHeader::previous(state.top) };
        }

        if state.top.is_null() {
            for region in &state.pool {
                region.reset();
            }
            self.publish_current_region(state);
            return;
        }

        let Some(index) = self.region_index_for_header(state, state.top) else {
            log::error!(
                "[scrap_heap] top allocation header missing: heap_id={:#x} header={:#x}",
                self.sheap_id,
                state.top as usize,
            );
            self.hot_region.store(ptr::null_mut(), Ordering::Release);
            return;
        };

        if !unsafe { state.pool[index].rewind_after(state.top) } {
            log::error!(
                "[scrap_heap] failed to rewind heap_id={:#x} header={:#x}",
                self.sheap_id,
                state.top as usize,
            );
            return;
        }

        for region in state.pool.iter().skip(index + 1) {
            region.reset();
        }
        self.publish_region(&state.pool[index]);
    }

    fn publish_current_region(&self, state: &HeapState) {
        if let Some(index) = self.current_region_index(state) {
            self.publish_region(&state.pool[index]);
        } else {
            self.hot_region.store(ptr::null_mut(), Ordering::Release);
        }
    }

    fn current_region_index(&self, state: &HeapState) -> Option<usize> {
        if state.pool.is_empty() {
            return None;
        }

        if state.top.is_null() {
            return Some(0);
        }

        self.region_index_for_header(state, state.top)
    }

    fn region_index_by_ptr(&self, state: &HeapState, ptr: *mut Region) -> Option<usize> {
        state
            .pool
            .iter()
            .position(|region| std::ptr::eq(&**region, ptr))
    }

    fn region_index_for_header(
        &self,
        state: &HeapState,
        header: *mut AllocationHeader,
    ) -> Option<usize> {
        state
            .pool
            .iter()
            .position(|region| region.contains_header(header))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{Heap, REGION_SIZE};
    use crate::mods::heap_replacer::scrap_heap::region::Region;
    use crate::mods::heap_replacer::scrap_heap::reserve::RegionReserve;
    use crate::mods::heap_replacer::scrap_heap::runtime::SeqQueue;

    fn heap_and_reserve() -> (Heap, Arc<RegionReserve>) {
        (
            Heap::new(0x1234, Arc::new(SeqQueue::new())),
            RegionReserve::create().unwrap(),
        )
    }

    #[test]
    fn live_allocation_blocks_checked_purge_then_releases_slot() {
        let (heap, reserve) = heap_and_reserve();
        let ptr = heap
            .try_alloc_slow_with_provider(64, 8, |_| {
                reserve.acquire().map(Region::from_reserved).map(Box::new)
            })
            .unwrap();

        assert_eq!(heap.checked_purge(), 0);
        assert_eq!(reserve.snapshot().in_use_regions, 1);

        heap.free(ptr);
        assert_eq!(heap.checked_purge(), 1);
        assert_eq!(reserve.snapshot().in_use_regions, 0);
    }

    #[test]
    fn oversized_request_preserves_requested_capacity() {
        let (heap, reserve) = heap_and_reserve();
        let size = REGION_SIZE + 4096;
        let ptr = heap
            .try_alloc_slow_with_provider(size, 16, |capacity| {
                assert!(capacity > REGION_SIZE);
                Region::new_dynamic(capacity).map(Box::new)
            })
            .unwrap();

        assert_eq!(reserve.snapshot().in_use_regions, 0);
        heap.free(ptr);
        assert_eq!(heap.checked_purge(), 1);
    }

    #[test]
    fn shared_heap_concurrent_alloc_free_keeps_one_region_owned() {
        let heap = Arc::new(Heap::new(0x5678, Arc::new(SeqQueue::new())));
        let reserve = RegionReserve::create().unwrap();
        let mut threads = Vec::new();

        for _ in 0..4 {
            let heap = Arc::clone(&heap);
            let reserve = Arc::clone(&reserve);
            threads.push(std::thread::spawn(move || {
                for _ in 0..128 {
                    let ptr = heap
                        .try_alloc_slow_with_provider(32, 8, |_| {
                            reserve.acquire().map(Region::from_reserved).map(Box::new)
                        })
                        .unwrap();
                    heap.free(ptr);
                }
            }));
        }

        for thread in threads {
            thread.join().unwrap();
        }

        assert_eq!(heap.alloc_count(), 0);
        assert_eq!(heap.checked_purge(), 1);
        assert_eq!(reserve.snapshot().in_use_regions, 0);
    }
}

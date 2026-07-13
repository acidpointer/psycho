use super::region::{ALLOCATION_HEADER_SIZE, AllocationHeader, Region};
use super::runtime::SeqQueue;

use crossfire::flavor::Queue;
use libc::c_void;
use parking_lot::Mutex;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

/// Default region size in bytes.
/// 128KB fits easily into fragmented 32-bit address space.
pub const REGION_SIZE: usize = 128 * 1024;

/// Region alignment.
const REGION_ALIGN: usize = 16;

const CACHE_LINE: usize = 64;

struct HeapState {
    // hot_region publishes Region addresses without taking the state lock.
    // Boxing keeps those addresses stable when the Vec grows or compacts.
    #[allow(clippy::vec_box)]
    pool: Vec<Box<Region>>,
    top: *mut AllocationHeader,
}

unsafe impl Send for HeapState {}

/// Scrap heap allocator for a single sheap identity.
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

    #[inline(always)]
    pub fn get_generation(&self) -> usize {
        self.generation.load(Ordering::Acquire)
    }

    /// Allocate with one caller-provided pre-reserved region fallback.
    pub fn try_alloc_slow_with_reserved<F>(
        &self,
        size: usize,
        align: usize,
        reserved_region: F,
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
        let mut boxed = match Region::new(region_capacity, REGION_ALIGN) {
            Some(region) => Box::new(region),
            None => reserved_region(region_capacity)?,
        };
        boxed.activate_accounting();

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

    #[inline]
    pub fn purge(&self) -> usize {
        let mut state = self.state.lock();
        self.purge_inner(&mut state)
    }

    /// GC-initiated purge. Only purges if no threads are actively using this heap.
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
        self.generation.fetch_add(1, Ordering::Release);

        old_len
    }

    pub fn region_count(&self) -> usize {
        self.state.lock().pool.len()
    }

    pub fn alloc_count(&self) -> usize {
        self.alloc_count.load(Ordering::Relaxed)
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

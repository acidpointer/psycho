#![allow(clippy::vec_box)]

use super::region::Region;
use super::runtime::SeqQueue;

use crossfire::flavor::Queue;
use libc::c_void;
use parking_lot::Mutex;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering, fence};
use std::sync::Arc;

/// Default region size in bytes.
/// 128KB fits easily into fragmented 32-bit address space.
const REGION_SIZE: usize = 128 * 1024;

/// Region alignment.
const REGION_ALIGN: usize = 16;

const CACHE_LINE: usize = 64;

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
    pool: Mutex<Vec<Box<Region>>>,
    gc_queued: AtomicBool,
    gc_queue: Arc<SeqQueue<usize>>,
    sheap_id: usize,
}

impl Heap {
    pub fn new(
        sheap_id: usize,
        gc_queue: Arc<SeqQueue<usize>>,
    ) -> Self {
        Self {
            hot_region: AtomicPtr::new(ptr::null_mut()),
            generation: AtomicUsize::new(0),
            _pad_read: [0; CACHE_LINE - 2 * size_of::<usize>()],
            alloc_count: AtomicUsize::new(0),
            _pad_write: [0; CACHE_LINE - size_of::<usize>()],
            pool: Mutex::new(Vec::with_capacity(8)),
            gc_queued: AtomicBool::new(false),
            gc_queue,
            sheap_id,
        }
    }

    #[inline(always)]
    pub fn get_generation(&self) -> usize {
        self.generation.load(Ordering::Acquire)
    }

    #[inline(always)]
    pub fn hot_region_ptr(&self) -> *const Region {
        self.hot_region.load(Ordering::Acquire)
    }

    /// Lock-free fast-path allocation from a TLC-cached region pointer.
    ///
    /// Uses a Dekker protocol with checked_purge to ensure the region
    /// pointer is still valid before dereferencing.
    #[inline]
    pub unsafe fn try_alloc_fast(
        &self,
        region: *const Region,
        size: usize,
        align: usize,
    ) -> Option<*mut c_void> {
        self.alloc_count.fetch_add(1, Ordering::AcqRel);

        if self.hot_region.load(Ordering::Acquire).is_null() {
            self.dec_alloc_count();
            return None;
        }

        if let Some(ptr) = unsafe { (*region).allocate(size, align) } {
            return Some(ptr.as_ptr());
        }

        self.dec_alloc_count();
        None
    }

    /// Slow path: takes Mutex, creates new region if needed.
    #[cold]
    pub fn try_alloc_slow(&self, size: usize, align: usize) -> Option<*mut c_void> {
        let mut pool = self.pool.lock();

        if let Some(last) = pool.last()
            && let Some(ptr) = last.allocate(size, align)
        {
            self.publish_region(last);
            self.alloc_count.fetch_add(1, Ordering::Relaxed);
            return Some(ptr.as_ptr());
        }

        let min_capacity = size.checked_add(align)?.checked_add(4)?;
        let region_capacity = REGION_SIZE.max(min_capacity);
        let region = Region::new(region_capacity, REGION_ALIGN)?;
        let ptr = region.allocate(size, align)?;

        let boxed = Box::new(region);
        self.publish_region(&boxed);
        pool.push(boxed);

        self.alloc_count.fetch_add(1, Ordering::Relaxed);
        Some(ptr.as_ptr())
    }

    #[inline]
    fn publish_region(&self, region: &Region) {
        self.hot_region
            .store(region as *const Region as *mut Region, Ordering::Release);
    }

    /// Decrement alloc_count and trigger GC if count reaches zero.
    #[inline]
    fn dec_alloc_count(&self) {
        loop {
            let current = self.alloc_count.load(Ordering::Acquire);
            if current == 0 {
                log::error!(
                    "[SBM] alloc_count underflow on sheap_id={:#x}",
                    self.sheap_id
                );
                return;
            }

            match self.alloc_count.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    if current == 1 {
                        self.try_enqueue_gc();
                    }
                    return;
                }
                Err(_) => continue,
            }
        }
    }

    #[inline]
    pub fn free(&self, _ptr: *mut c_void) {
        self.dec_alloc_count();
    }

    #[inline]
    fn try_enqueue_gc(&self) {
        if self.gc_queued.swap(true, Ordering::AcqRel) {
            return;
        }

        if let Err(failed_id) = self.gc_queue.push(self.sheap_id) {
            log::error!("[SBM] GC queue push failed for sheap_id={:#x}", failed_id);
            self.gc_queued.store(false, Ordering::Release);
        }
    }

    #[inline]
    pub fn purge(&self) -> usize {
        let mut pool = self.pool.lock();
        self.purge_inner(&mut pool)
    }

    /// GC-initiated purge. Only purges if no threads are actively using this heap.
    #[inline]
    pub fn checked_purge(&self) -> usize {
        self.gc_queued.store(false, Ordering::Release);

        let mut pool = self.pool.lock();

        self.hot_region
            .store(ptr::null_mut(), Ordering::Release);
        fence(Ordering::SeqCst);

        if self.alloc_count.load(Ordering::Acquire) != 0 {
            if let Some(last) = pool.last() {
                self.publish_region(last);
            }
            return 0;
        }

        self.purge_inner(&mut pool)
    }

    fn purge_inner(&self, pool: &mut Vec<Box<Region>>) -> usize {
        self.hot_region
            .store(ptr::null_mut(), Ordering::Release);

        let old_len = pool.len();
        pool.clear();

        self.alloc_count.store(0, Ordering::Release);
        self.gc_queued.store(false, Ordering::Release);
        self.generation.fetch_add(1, Ordering::Release);

        old_len
    }
}

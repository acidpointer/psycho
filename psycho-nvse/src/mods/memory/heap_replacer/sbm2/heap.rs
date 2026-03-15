#![allow(clippy::vec_box)]

use super::region::Region;
use super::stats::AllocatorStats;
use super::runtime::SeqQueue;

use crossfire::flavor::Queue;
use libc::c_void;
use parking_lot::Mutex;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering, fence};

/// Region size in bytes
/// Recommended values:
/// * MIN: 128Kb
/// * MAX: 512Kb (extreme)
/// # Notes
/// * `REGION_SIZE` < `128Kb` will lead to crashes!
/// * `REGION_SIZE` > `512Kb` will lead to OOM(Out-Of-Memory)!
const REGION_SIZE: usize = 256 * 1024;

/// Region alignment
const REGION_ALIGN: usize = 16;

pub struct Heap {
    /// Region pool — Mutex, only taken on slow path (new region / purge).
    /// Box<Region> ensures stable pointers across Vec growth.
    pool: Mutex<Vec<Box<Region>>>,

    /// Current (last) region for lock-free fast-path allocation.
    /// Loaded with Acquire, stored with Release. Null after purge.
    hot_region: AtomicPtr<Region>,

    /// Shared allocator statistics — owned by Runtime, outlives all Heaps.
    stats: Arc<AllocatorStats>,

    /// Live allocation count.
    /// Pre-incremented on fast path to prevent concurrent GC purge.
    alloc_count: AtomicUsize,

    /// Whether this heap's ID is already in the GC queue.
    /// Prevents duplicate pushes on rapid alloc/free cycles.
    gc_queued: AtomicBool,

    /// Reference to the shared GC queue
    gc_queue: Arc<SeqQueue<usize>>,

    /// Sheap identity (the sheap_ptr address used as key)
    sheap_id: usize,

    /// Generation counter — incremented on purge to invalidate TLC entries
    generation: AtomicUsize,
}

impl Heap {
    pub fn new(
        sheap_id: usize,
        gc_queue: Arc<SeqQueue<usize>>,
        stats: Arc<AllocatorStats>,
    ) -> Self {
        Self {
            pool: Mutex::new(Vec::with_capacity(8)),
            hot_region: AtomicPtr::new(ptr::null_mut()),
            gc_queue,
            stats,
            alloc_count: AtomicUsize::new(0),
            gc_queued: AtomicBool::new(false),
            sheap_id,
            generation: AtomicUsize::new(0),
        }
    }

    #[inline(always)]
    pub fn get_generation(&self) -> usize {
        self.generation.load(Ordering::Acquire)
    }

    /// Lock-free fast-path allocation.
    ///
    /// Pre-increments `alloc_count` to prevent concurrent GC purge from
    /// freeing the hot region while we're using it. Rolls back on failure.
    ///
    /// Caller must have validated generation (TLC check).
    #[inline]
    pub fn try_alloc_fast(&self, size: usize, align: usize) -> Option<*mut c_void> {
        // Pre-increment: prevents GC checked_purge from seeing 0 and purging
        self.alloc_count.fetch_add(1, Ordering::Relaxed);

        let region = self.hot_region.load(Ordering::Acquire);
        if !region.is_null()
            && let Some(ptr) = unsafe { &*region }.allocate(size, align) {
                return Some(ptr.as_ptr());
            }

        // Allocation failed — rollback the pre-increment
        self.rollback_alloc_count();
        None
    }

    /// Slow path — takes Mutex, creates new region if needed.
    #[cold]
    pub fn try_alloc_slow(&self, size: usize, align: usize) -> Option<*mut c_void> {
        let mut pool = self.pool.lock();

        // Re-check: another thread may have pushed a new region while we waited
        if let Some(last) = pool.last()
            && let Some(ptr) = last.allocate(size, align) {
                self.hot_region.store(&**last as *const Region as *mut Region, Ordering::Release);
                self.alloc_count.fetch_add(1, Ordering::Relaxed);
                return Some(ptr.as_ptr());
            }

        // Oversized allocations get a dedicated region
        let region_capacity = REGION_SIZE.max(size + align + 4);

        // Pass &AllocatorStats — Region stores raw pointer, no Arc clone
        let region = Region::new(region_capacity, REGION_ALIGN, &self.stats)?;
        let ptr = region.allocate(size, align)?;

        let boxed = Box::new(region);
        let region_ptr = &*boxed as *const Region as *mut Region;
        pool.push(boxed);

        self.hot_region.store(region_ptr, Ordering::Release);
        self.alloc_count.fetch_add(1, Ordering::Relaxed);

        Some(ptr.as_ptr())
    }

    /// Rollback a pre-incremented alloc_count and check if GC should be queued.
    #[inline]
    fn rollback_alloc_count(&self) {
        let prev = self.alloc_count.fetch_sub(1, Ordering::Relaxed);

        // If our rollback dropped count to 0, another thread's free() may have
        // missed the prev==1 trigger. Enqueue for GC to prevent leak.
        if prev == 1 {
            self.try_enqueue_gc();
        }
    }

    /// Decrements the allocation count and enqueues for GC if count reaches zero.
    #[inline]
    pub fn free(&self, _ptr: *mut c_void) {
        let prev = self.alloc_count.fetch_sub(1, Ordering::Release);

        // prev is the value BEFORE subtraction, so prev == 1 means new count is 0
        if prev == 1 {
            self.try_enqueue_gc();
        }
    }

    /// Enqueue this heap for GC if not already queued.
    #[inline]
    fn try_enqueue_gc(&self) {
        if !self.gc_queued.swap(true, Ordering::Acquire)
            && let Err(failed_id) = self.gc_queue.push(self.sheap_id) {
                log::error!(
                    "heap: failed to push sheap_id={:#x} to gc_queue!",
                    failed_id
                );
                self.gc_queued.store(false, Ordering::Release);
            }
    }

    /// Purge all regions. Called by game-initiated sheap resets.
    ///
    /// Resets alloc_count and bumps generation to invalidate TLC entries.
    ///
    /// # Warning
    /// All allocations from this heap become invalid after this call.
    /// Game must ensure no concurrent allocations on this sheap.
    #[inline]
    pub fn purge(&self) -> usize {
        let mut pool = self.pool.lock();
        self.purge_inner(&mut pool)
    }

    /// GC-initiated purge. Only purges if no threads are actively using this heap.
    ///
    /// Uses Dekker-style mutual exclusion with `try_alloc_fast`:
    /// - GC writes `hot_region = null`, then reads `alloc_count`
    /// - Allocator writes `alloc_count += 1`, then reads `hot_region`
    /// - SeqCst fence ensures at least one side sees the other's write
    ///
    /// This guarantees: either GC sees alloc_count > 0 (aborts), or the
    /// allocator sees hot_region == null (gets None, rolls back).
    #[inline]
    pub fn checked_purge(&self) -> usize {
        self.gc_queued.store(false, Ordering::Release);

        // Quick check without lock — avoids Mutex if heap is active
        if self.alloc_count.load(Ordering::Acquire) != 0 {
            return 0;
        }

        let mut pool = self.pool.lock();

        // Null hot_region under Mutex: no new fast-path allocs can succeed after this
        self.hot_region.store(ptr::null_mut(), Ordering::Release);

        // SeqCst fence: prevents x86 store-load reorder between the null store
        // above and the alloc_count re-check below. Without this, GC could read
        // a stale alloc_count == 0 while a thread already loaded the old hot_region.
        fence(Ordering::SeqCst);

        // Re-check: a fast-path alloc may have pre-incremented between our
        // lockless check and nulling hot_region. Since hot_region is now null,
        // no new fast-path allocs can succeed — but an in-flight one may have
        // already loaded the old pointer. If alloc_count > 0, that thread is
        // still using the region, so we must NOT free it.
        if self.alloc_count.load(Ordering::Acquire) != 0 {
            // Restore hot_region — someone has an active allocation
            if let Some(last) = pool.last() {
                self.hot_region.store(
                    &**last as *const Region as *mut Region,
                    Ordering::Release,
                );
            }
            return 0;
        }

        // alloc_count == 0 AND hot_region is null → safe to purge
        self.purge_inner(&mut pool)
    }

    /// Actual purge logic. Caller must hold the Mutex.
    fn purge_inner(&self, pool: &mut Vec<Box<Region>>) -> usize {
        self.hot_region.store(ptr::null_mut(), Ordering::Release);

        let old_len = pool.len();
        pool.clear();

        // Reset state
        self.alloc_count.store(0, Ordering::Release);
        self.gc_queued.store(false, Ordering::Release);
        self.generation.fetch_add(1, Ordering::Release);

        old_len
    }
}

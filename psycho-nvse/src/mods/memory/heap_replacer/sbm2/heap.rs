#![allow(clippy::vec_box)]

use super::region::Region;
use super::runtime::SeqQueue;
use super::stats::AllocatorStats;

use crossfire::flavor::Queue;
use libc::c_void;
use parking_lot::Mutex;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering, fence};
use std::sync::Arc;

/// Default region size in bytes.
/// 128KB fits easily into fragmented 32-bit address space.
/// Oversized allocations get dedicated regions via REGION_SIZE.max(size + align + 4).
const REGION_SIZE: usize = 128 * 1024;

/// Region alignment.
const REGION_ALIGN: usize = 16;

// ---------------------------------------------------------------------------
// Cache line layout
// ---------------------------------------------------------------------------
//
//   Line 1 (offset 0):   hot_region, generation    - READ-heavy on fast path
//   Line 2 (offset 64):  alloc_count               - RMW on every alloc/free
//   Line 3+ (offset 128): pool, stats, gc_*        - cold (slow path / purge)

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
    stats: Arc<AllocatorStats>,
    gc_queued: AtomicBool,
    gc_queue: Arc<SeqQueue<usize>>,
    sheap_id: usize,
}

impl Heap {
    pub fn new(
        sheap_id: usize,
        gc_queue: Arc<SeqQueue<usize>>,
        stats: Arc<AllocatorStats>,
    ) -> Self {
        Self {
            hot_region: AtomicPtr::new(ptr::null_mut()),
            generation: AtomicUsize::new(0),
            _pad_read: [0; CACHE_LINE - 2 * size_of::<usize>()],
            alloc_count: AtomicUsize::new(0),
            _pad_write: [0; CACHE_LINE - size_of::<usize>()],
            pool: Mutex::new(Vec::with_capacity(8)),
            stats,
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
    /// # Dekker protocol (GC safety)
    ///
    /// ```text
    /// Allocator (this fn)           GC (checked_purge)
    /// ---------------------         ----------------------
    /// alloc_count += 1 (AcqRel)     hot_region = null (Release)
    ///                               SeqCst fence
    /// read hot_region (Acquire)     read alloc_count (Acquire)
    /// ```
    ///
    /// AcqRel on fetch_add ensures the increment is visible to GC before
    /// we read hot_region, satisfying the Dekker mutual exclusion.
    ///
    /// # Safety
    ///
    /// `region` must point to a `Region` in this Heap's pool, obtained while
    /// the current generation was valid.
    #[inline]
    pub unsafe fn try_alloc_fast(
        &self,
        region: *const Region,
        size: usize,
        align: usize,
    ) -> Option<*mut c_void> {
        // Step 1: pre-increment with AcqRel barrier (Dekker write)
        self.alloc_count.fetch_add(1, Ordering::AcqRel);

        // Step 2: Dekker check - if GC nulled hot_region, purge may be active
        if self.hot_region.load(Ordering::Acquire).is_null() {
            self.dec_alloc_count();
            return None;
        }

        // Step 3: safe to dereference - Dekker guarantees region is alive
        if let Some(ptr) = unsafe { (*region).allocate(size, align) } {
            return Some(ptr.as_ptr());
        }

        self.dec_alloc_count();
        None
    }

    /// Slow path - takes Mutex, creates new region if needed.
    #[cold]
    pub fn try_alloc_slow(&self, size: usize, align: usize) -> Option<*mut c_void> {
        let mut pool = self.pool.lock();

        // Re-check: another thread may have pushed a new region while we waited
        if let Some(last) = pool.last()
            && let Some(ptr) = last.allocate(size, align) {
                self.publish_region(last);
                self.alloc_count.fetch_add(1, Ordering::Relaxed);
                return Some(ptr.as_ptr());
            }

        // Create new region. Checked arithmetic prevents overflow on 32-bit.
        let min_capacity = size.checked_add(align)?.checked_add(4)?;
        let region_capacity = REGION_SIZE.max(min_capacity);
        let region = Region::new(region_capacity, REGION_ALIGN, &self.stats)?;
        let ptr = region.allocate(size, align)?;

        let boxed = Box::new(region);
        self.publish_region(&boxed);
        pool.push(boxed);

        self.alloc_count.fetch_add(1, Ordering::Relaxed);
        Some(ptr.as_ptr())
    }

    /// Publish a region pointer to hot_region for TLC caching.
    #[inline]
    fn publish_region(&self, region: &Region) {
        self.hot_region
            .store(region as *const Region as *mut Region, Ordering::Release);
    }

    /// Decrement alloc_count and trigger GC if count reaches zero.
    /// Handles underflow defensively (game bugs: double-free, free-after-purge).
    #[inline]
    fn dec_alloc_count(&self) {
        let prev = self.alloc_count.fetch_sub(1, Ordering::Release);

        if prev == 0 {
            // Underflow: was already 0 before sub. Roll back to prevent wrap.
            self.alloc_count.fetch_add(1, Ordering::Relaxed);
            log::error!(
                "[SBM] alloc_count underflow on sheap_id={:#x}",
                self.sheap_id
            );
            return;
        }

        if prev == 1 {
            self.try_enqueue_gc();
        }
    }

    /// Decrements allocation count. Called by Runtime::free().
    #[inline]
    pub fn free(&self, _ptr: *mut c_void) {
        self.dec_alloc_count();
    }

    /// Enqueue this heap for GC if not already queued.
    #[inline]
    fn try_enqueue_gc(&self) {
        if self.gc_queued.swap(true, Ordering::AcqRel) {
            return; // already queued
        }

        if let Err(failed_id) = self.gc_queue.push(self.sheap_id) {
            log::error!("[SBM] GC queue push failed for sheap_id={:#x}", failed_id);
            // Reset so future frees can retry
            self.gc_queued.store(false, Ordering::Release);
        }
    }

    /// Purge all regions. Called by game-initiated sheap resets.
    #[inline]
    pub fn purge(&self) -> usize {
        let mut pool = self.pool.lock();
        self.purge_inner(&mut pool)
    }

    /// GC-initiated purge. Only purges if no threads are actively using this heap.
    ///
    /// Dekker protocol: null hot_region UNDER MUTEX, then check alloc_count.
    /// This prevents the TOCTOU race where an allocation sneaks in between
    /// the lockless check and the purge.
    #[inline]
    pub fn checked_purge(&self) -> usize {
        self.gc_queued.store(false, Ordering::Release);

        // Take Mutex FIRST to prevent new slow-path allocations
        let mut pool = self.pool.lock();

        // Null hot_region: fast-path allocations will abort after seeing null
        self.hot_region
            .store(ptr::null_mut(), Ordering::Release);

        // SeqCst fence: ensures the null store above is visible before
        // we read alloc_count below (prevents x86 store-load reorder)
        fence(Ordering::SeqCst);

        // Check if any allocations are in flight
        if self.alloc_count.load(Ordering::Acquire) != 0 {
            // Restore hot_region - allocations are still active
            if let Some(last) = pool.last() {
                self.publish_region(last);
            }
            return 0;
        }

        // alloc_count == 0 AND hot_region is null -> safe to purge
        self.purge_inner(&mut pool)
    }

    /// Actual purge logic. Caller must hold the Mutex.
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

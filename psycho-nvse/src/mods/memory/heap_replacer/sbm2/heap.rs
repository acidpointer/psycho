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

// ---------------------------------------------------------------------------
// Cache line layout
// ---------------------------------------------------------------------------
//
// On x86, a cache line is 64 bytes. When multiple atomic fields share the
// same cache line, writing to *any* of them invalidates the entire line for
// every other core -- even cores that only *read* a different field on that
// line. This is called "false sharing".
//
// The Heap struct is laid out so that fields with different access patterns
// live on **separate cache lines**:
//
//   Line 1 (offset 0):   hot_region, generation    - READ-heavy on fast path
//   Line 2 (offset 64):  alloc_count               - READ-WRITE (fetch_add/sub) on every alloc/free
//   Line 3+ (offset 128): pool, stats, gc_*        - cold (slow path / purge only)
//
// This means:
// - `alloc_count` bouncing between cores (alloc <-> free) does NOT invalidate
//   the line holding `hot_region`/`generation`, so Dekker checks and TLC
//   generation reads stay fast.
// - `hot_region` writes (rare: GC purge, slow-path publish) do NOT invalidate
//   the `alloc_count` line.

const CACHE_LINE: usize = 64;

/// Scrap heap allocator for a single sheap identity.
///
/// See module-level docs for the cache line layout rationale.
#[repr(C, align(64))]
pub struct Heap {
    // === Cache line 1: read-heavy on fast path ===
    /// Dekker signal + last published region pointer.
    ///
    /// - Non-null: points to the most recently created/used `Region` in the pool.
    ///   Used by `try_alloc_fast` purely as a **Dekker signal** (null = GC active).
    ///   Also used by Runtime to seed the TLC region cache on cold path.
    /// - Null: GC may be purging -- fast path must abort.
    hot_region: AtomicPtr<Region>,

    /// Generation counter -- incremented on purge to invalidate TLC entries.
    generation: AtomicUsize,

    // Pad to fill the rest of cache line 1.
    // 2 * usize (AtomicPtr + AtomicUsize) on i686 = 8 bytes, pad to 64.
    _pad_read: [u8; CACHE_LINE - 2 * size_of::<usize>()],

    // === Cache line 2: RMW-heavy on fast path ===
    /// Live allocation count.
    ///
    /// Incremented on every successful allocation (fast or slow path),
    /// decremented on every `free()`. When it reaches 0, the heap is
    /// enqueued for GC.
    ///
    /// Also serves as the allocator side of the Dekker protocol:
    /// fast path does `alloc_count += 1` **before** reading `hot_region`,
    /// preventing GC from seeing count == 0 while an allocation is in flight.
    alloc_count: AtomicUsize,

    _pad_write: [u8; CACHE_LINE - size_of::<usize>()],

    // === Cache line 3+: cold (slow path / purge only) ===
    /// Region pool -- Mutex, only taken on slow path (new region / purge).
    /// `Box<Region>` ensures stable pointers across `Vec` growth.
    pool: Mutex<Vec<Box<Region>>>,

    /// Shared allocator statistics -- owned by Runtime, outlives all Heaps.
    stats: Arc<AllocatorStats>,

    /// Whether this heap's ID is already in the GC queue.
    gc_queued: AtomicBool,

    /// Reference to the shared GC queue.
    gc_queue: Arc<SeqQueue<usize>>,

    /// Sheap identity (the sheap_ptr address used as key).
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

    /// Returns the current generation. Used by TLC to detect stale entries.
    #[inline(always)]
    pub fn get_generation(&self) -> usize {
        self.generation.load(Ordering::Acquire)
    }

    /// Returns a raw pointer to the current hot region (may be null).
    ///
    /// Used by Runtime to seed the TLC region cache after a slow-path
    /// allocation or cold-path lookup. The returned pointer is valid
    /// as long as the generation hasn't changed (i.e., no purge occurred).
    #[inline(always)]
    pub fn hot_region_ptr(&self) -> *const Region {
        self.hot_region.load(Ordering::Acquire)
    }

    /// Lock-free fast-path allocation from a TLC-cached region pointer.
    ///
    /// The caller provides a raw `*const Region` from its thread-local cache.
    /// This pointer is only dereferenced AFTER the Dekker protocol confirms
    /// no GC purge is in progress, ensuring the region is still alive.
    ///
    /// # Dekker protocol (GC safety)
    ///
    /// The pre-increment of `alloc_count` and the `hot_region` null-check form
    /// a Dekker-style mutual exclusion with `checked_purge`:
    ///
    /// ```text
    /// Allocator (this fn)           GC (checked_purge)
    /// ---------------------         ----------------------
    /// alloc_count += 1              hot_region = null
    ///   | (x86: lock xadd             | (store)
    ///      = full barrier)          SeqCst fence (mfence)
    /// read hot_region               read alloc_count
    /// ```
    ///
    /// At least one side sees the other's write:
    /// - If the allocator sees `hot_region == null` -> aborts, rolls back count.
    /// - If GC sees `alloc_count > 0` -> aborts purge.
    /// - Both seeing the other's write is also safe (allocator aborts).
    ///
    /// On x86, `lock xadd` (fetch_add) provides a full barrier, so no
    /// explicit fence is needed on the allocator side.
    ///
    /// # Safety
    ///
    /// `region` must point to a `Region` in this Heap's pool, obtained while
    /// the current generation was valid. The pointer is only dereferenced
    /// after the Dekker check confirms no purge is in progress.
    #[inline]
    pub unsafe fn try_alloc_fast(&self, region: *const Region, size: usize, align: usize) -> Option<*mut c_void> {
        // Step 1: pre-increment (Dekker: write alloc_count)
        self.alloc_count.fetch_add(1, Ordering::Relaxed);

        // Step 2: Dekker check (read hot_region as GC signal)
        // If GC nulled hot_region, a purge may be in progress.
        // On x86, the preceding lock xadd acts as a full barrier, so this
        // load is guaranteed to see the null store if it happened before
        // our fetch_add.
        if self.hot_region.load(Ordering::Acquire).is_null() {
            self.rollback_alloc_count();
            return None;
        }

        // Step 3: SAFE to dereference -- Dekker guarantees the region is alive.
        // If GC had purged (freeing this region), it would have nulled
        // hot_region first, and we would have returned None above.
        if let Some(ptr) = unsafe { (*region).allocate(size, align) } {
            return Some(ptr.as_ptr());
        }

        self.rollback_alloc_count();
        None
    }

    /// Slow path -- takes Mutex, creates new region if needed.
    ///
    /// After a successful allocation, `hot_region` is updated to point to
    /// the used region. The caller should read `hot_region_ptr()` to update
    /// its thread-local region cache.
    #[cold]
    pub fn try_alloc_slow(&self, size: usize, align: usize) -> Option<*mut c_void> {
        let mut pool = self.pool.lock();

        // Re-check: another thread may have pushed a new region while we waited
        if let Some(last) = pool.last()
            && let Some(ptr) = last.allocate(size, align)
        {
            self.hot_region
                .store(&**last as *const Region as *mut Region, Ordering::Release);
            self.alloc_count.fetch_add(1, Ordering::Relaxed);
            return Some(ptr.as_ptr());
        }

        // Oversized allocations get a dedicated region
        let region_capacity = REGION_SIZE.max(size + align + 4);

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
    ///
    /// This should never underflow because we only call it after a successful
    /// fetch_add. The check is defensive against hypothetical bugs.
    #[inline]
    fn rollback_alloc_count(&self) {
        let prev = self.alloc_count.fetch_sub(1, Ordering::Relaxed);

        debug_assert!(prev > 0, "rollback_alloc_count: underflow on sheap_id={:#x}", self.sheap_id);

        if prev == 0 {
            self.alloc_count.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // If our rollback dropped count to 0, another thread's free() may have
        // missed the prev==1 trigger. Enqueue for GC to prevent leak.
        if prev == 1 {
            self.try_enqueue_gc();
        }
    }

    /// Decrements the allocation count and enqueues for GC if count reaches zero.
    ///
    /// Detects underflow (game bug: double-free, free-after-purge, or wrong
    /// sheap_ptr). On underflow the decrement is rolled back to prevent
    /// alloc_count from wrapping to usize::MAX, which would permanently
    /// prevent GC from collecting this heap.
    #[inline]
    pub fn free(&self, _ptr: *mut c_void) {
        let prev = self.alloc_count.fetch_sub(1, Ordering::Release);

        if prev == 0 {
            // Underflow: count was already 0 before this free().
            // Roll back to keep count at 0 instead of usize::MAX.
            self.alloc_count.fetch_add(1, Ordering::Relaxed);
            log::error!(
                "heap: alloc_count underflow on sheap_id={:#x} (double-free or free-after-purge)",
                self.sheap_id
            );
            return;
        }

        // prev is the value BEFORE subtraction, so prev == 1 means new count is 0
        if prev == 1 {
            self.try_enqueue_gc();
        }
    }

    /// Enqueue this heap for GC if not already queued.
    #[inline]
    fn try_enqueue_gc(&self) {
        if !self.gc_queued.swap(true, Ordering::Acquire)
            && let Err(failed_id) = self.gc_queue.push(self.sheap_id)
        {
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
    /// Uses Dekker-style mutual exclusion with `try_alloc_fast` -- see the
    /// protocol diagram in `try_alloc_fast` docs.
    #[inline]
    pub fn checked_purge(&self) -> usize {
        self.gc_queued.store(false, Ordering::Release);

        // Quick check without lock -- avoids Mutex if heap is active
        if self.alloc_count.load(Ordering::Acquire) != 0 {
            return 0;
        }

        let mut pool = self.pool.lock();

        // Null hot_region under Mutex: no new fast-path allocs can succeed after this
        self.hot_region.store(ptr::null_mut(), Ordering::Release);

        // SeqCst fence: prevents x86 store-load reorder between the null store
        // above and the alloc_count re-check below.
        fence(Ordering::SeqCst);

        // Re-check: a fast-path alloc may have pre-incremented between our
        // lockless check and nulling hot_region. If alloc_count > 0, that thread
        // is still using a region -- we must NOT free it.
        if self.alloc_count.load(Ordering::Acquire) != 0 {
            if let Some(last) = pool.last() {
                self.hot_region.store(
                    &**last as *const Region as *mut Region,
                    Ordering::Release,
                );
            }
            return 0;
        }

        // alloc_count == 0 AND hot_region is null -> safe to purge
        self.purge_inner(&mut pool)
    }

    /// Actual purge logic. Caller must hold the Mutex.
    ///
    /// Non-zero alloc_count at purge time is normal for scrap heaps -- the game
    /// bulk-allocates then purges without individual frees.
    fn purge_inner(&self, pool: &mut Vec<Box<Region>>) -> usize {
        self.hot_region.store(ptr::null_mut(), Ordering::Release);

        let old_len = pool.len();
        pool.clear();

        // Reset state. alloc_count > 0 is expected (scrap heap pattern:
        // bulk alloc then purge without individual frees).
        self.alloc_count.store(0, Ordering::Release);
        self.gc_queued.store(false, Ordering::Release);
        self.generation.fetch_add(1, Ordering::Release);

        old_len
    }
}

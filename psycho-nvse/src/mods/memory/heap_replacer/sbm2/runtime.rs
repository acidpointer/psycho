use std::cell::Cell;
use std::ptr::{self, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossfire::flavor::Queue;
use libc::c_void;

use super::heap::Heap;
use super::region::Region;
use super::stats::AllocatorStats;

pub type SeqQueue<T> = crossfire::flavor::List<T>;

/// Duration between GC cycles
const GC_DURATION: Duration = Duration::from_millis(1000 * 5);

/// ClashMap with FxHasher
type HeapMap<K, V> = clashmap::ClashMap<K, V, rustc_hash::FxBuildHasher>;

// ---------------------------------------------------------------------------
// Thread-Local Cache (TLC)
// ---------------------------------------------------------------------------
//
// Each thread caches a pointer to the last-used Heap and Region, avoiding
// the ClashMap lookup and reducing contention on the Region's atomic offset.
//
// # Safety invariants
//
// The raw pointers stored here are safe to dereference as long as
// `Heap::get_generation() == generation`:
//
// - `heap: *const Heap` -- points into an `Arc<Heap>` inside the ClashMap.
//   The ClashMap never removes entries, so the Arc (and thus the Heap)
//   is never dropped during normal operation.
//
// - `region: *const Region` -- points into a `Box<Region>` inside the Heap's
//   pool Vec. Box provides pointer stability across Vec growth. The pool is
//   only cleared during purge, which bumps `generation`, invalidating this
//   cache entry before the pointer can be used.

#[derive(Clone, Copy)]
struct TlcEntry {
    sheap_id: usize,
    generation: usize,
    heap: *const Heap,
    region: *const Region,
}

impl TlcEntry {
    const fn empty() -> Self {
        Self {
            sheap_id: 0,
            generation: 0,
            heap: ptr::null(),
            region: ptr::null(),
        }
    }
}

thread_local! {
    static TLC: Cell<TlcEntry> = const { Cell::new(TlcEntry::empty()) };
}

pub struct Runtime {
    /// Stats shared down to region layer
    stats: Arc<AllocatorStats>,

    /// HeapMap: sheap_ptr (as usize) -> Arc<Heap>
    pool: Arc<HeapMap<usize, Arc<Heap>>>,

    /// GC queue: sheap IDs ready for checked_purge
    gc_queue: Arc<SeqQueue<usize>>,

    /// Control flag for GC thread
    gc_run: Arc<AtomicBool>,

    /// GC thread handle
    gc_handle: Option<JoinHandle<()>>,
}

unsafe impl Send for Runtime {}
unsafe impl Sync for Runtime {}

impl Runtime {
    pub fn new() -> Self {
        let gc_run = Arc::new(AtomicBool::new(true));

        let mut instance = Self {
            stats: Arc::new(AllocatorStats::new()),
            pool: Arc::new(HeapMap::default()),
            gc_queue: Arc::new(SeqQueue::new()),
            gc_run: gc_run.clone(),
            gc_handle: None,
        };

        instance.init_gc();
        instance
    }

    fn init_gc(&mut self) {
        let gc_run = self.gc_run.clone();
        let pool = self.pool.clone();
        let stats = self.stats.clone();
        let gc_queue = self.gc_queue.clone();

        let gc_handle = thread::spawn(move || {
            loop {
                if !gc_run.load(Ordering::Acquire) {
                    return;
                }

                thread::sleep(GC_DURATION);

                let curr_mem = stats.get_total_alloc_mem();
                let heaps_len = pool.len();

                log::info!(
                    "[SBM] Memory: {} MB ({} KB, {} B); Heaps: {}",
                    curr_mem / 1024 / 1024,
                    curr_mem / 1024,
                    curr_mem,
                    heaps_len
                );

                while let Some(sheap_id) = gc_queue.pop() {
                    if let Some(heap) = pool.get(&sheap_id) {
                        let purged = heap.checked_purge();

                        if purged > 0 {
                            log::debug!(
                                "[GC] sheap_id={:#x}: purged {} regions",
                                sheap_id,
                                purged
                            );
                        }
                    }
                }
            }
        });

        self.gc_handle = Some(gc_handle);
    }

    /// Looks up or creates a Heap for the given sheap_id.
    ///
    /// Returns an `Arc<Heap>` clone. The ClashMap shard lock is released
    /// before returning, so the caller can do slow work (Mutex, mi_malloc)
    /// without blocking other threads in the same shard.
    #[cold]
    fn get_or_create_heap(&self, sheap_id: usize) -> Arc<Heap> {
        let guard = self.pool.entry(sheap_id).or_insert_with(|| {
            Arc::new(Heap::new(
                sheap_id,
                self.gc_queue.clone(),
                self.stats.clone(),
            ))
        });
        Arc::clone(&guard)
        // `guard` dropped here -> shard lock released
    }

    /// Resolves sheap_ptr to a Heap via TLC (fast) or ClashMap (slow).
    /// Used by `free()` and `purge()` which don't need region caching.
    #[inline]
    fn with_heap<R>(&self, sheap_ptr: *mut c_void, f: impl FnOnce(&Heap) -> R) -> R {
        let sheap_id = sheap_ptr as usize;
        let tlc = TLC.with(|c| c.get());

        if tlc.sheap_id == sheap_id && !tlc.heap.is_null() {
            // SAFETY: see TLC safety invariants at the top of this file.
            let heap = unsafe { &*tlc.heap };

            if heap.get_generation() == tlc.generation {
                return f(heap);
            }
        }

        self.with_heap_slow(sheap_id, f)
    }

    /// Slow path for `with_heap`: ClashMap lookup, TLC refresh.
    #[cold]
    fn with_heap_slow<R>(&self, sheap_id: usize, f: impl FnOnce(&Heap) -> R) -> R {
        let heap = self.get_or_create_heap(sheap_id);
        let generation = heap.get_generation();

        TLC.with(|c| {
            c.set(TlcEntry {
                sheap_id,
                generation,
                heap: &*heap as *const Heap,
                region: heap.hot_region_ptr(),
            });
        });

        f(&heap)
    }

    /// Allocates memory from the scrap heap.
    ///
    /// Three-tier fast path:
    /// 1. **Ultra-fast** -- TLC hit + cached region bump (per-thread, no offset contention)
    /// 2. **Slow** -- TLC hit but region full -> Mutex + new region
    /// 3. **Cold** -- TLC miss -> ClashMap lookup + slow alloc
    #[inline]
    pub fn alloc(&self, sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
        let sheap_id = sheap_ptr as usize;
        let tlc = TLC.with(|c| c.get());

        if tlc.sheap_id == sheap_id && !tlc.heap.is_null() {
            // SAFETY: see TLC safety invariants at the top of this file.
            let heap = unsafe { &*tlc.heap };

            if heap.get_generation() == tlc.generation {
                // Ultra-fast: lock-free bump from per-thread cached region.
                // Each thread typically has its own region, so offset.fetch_add
                // doesn't contend with other threads.
                if !tlc.region.is_null() {
                    // SAFETY: region pointer validated by generation check above.
                    let region = unsafe { &*tlc.region };

                    if let Some(ptr) = heap.try_alloc_fast(region, size, align) {
                        return ptr;
                    }
                }

                // Cached region full or null: slow path (Mutex, new region)
                return self.alloc_slow(heap, tlc, size, align);
            }
        }

        // Cold: ClashMap lookup
        self.alloc_cold(sheap_id, size, align)
    }

    /// Slow-path allocation: Mutex + new region creation.
    /// Updates TLC with the new hot region for future fast-path hits.
    #[cold]
    fn alloc_slow(&self, heap: &Heap, tlc: TlcEntry, size: usize, align: usize) -> *mut c_void {
        match heap.try_alloc_slow(size, align) {
            Some(ptr) => {
                // Cache the region that try_alloc_slow published
                TLC.with(|c| {
                    c.set(TlcEntry {
                        region: heap.hot_region_ptr(),
                        ..tlc
                    });
                });
                ptr
            }
            None => null_mut(),
        }
    }

    /// Cold-path allocation: ClashMap lookup + slow alloc.
    #[cold]
    fn alloc_cold(&self, sheap_id: usize, size: usize, align: usize) -> *mut c_void {
        let heap = self.get_or_create_heap(sheap_id);

        match heap.try_alloc_slow(size, align) {
            Some(ptr) => {
                let generation = heap.get_generation();
                TLC.with(|c| {
                    c.set(TlcEntry {
                        sheap_id,
                        generation,
                        heap: &*heap as *const Heap,
                        region: heap.hot_region_ptr(),
                    });
                });
                ptr
            }
            None => null_mut(),
        }
    }

    #[inline]
    pub fn free(&self, sheap_ptr: *mut c_void, ptr: *mut c_void) {
        if ptr.is_null() {
            return;
        }

        self.with_heap(sheap_ptr, |heap| {
            heap.free(ptr);
        })
    }

    #[inline]
    pub fn purge(&self, sheap_ptr: *mut c_void) -> usize {
        self.with_heap(sheap_ptr, |heap| heap.purge())
    }

    /// Singleton
    pub fn get_instance() -> &'static Self {
        static RT: LazyLock<Runtime> = LazyLock::new(Runtime::new);
        &RT
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.gc_run.store(false, Ordering::Release);

        if let Some(handle) = self.gc_handle.take() {
            let _ = handle.join();
        }
    }
}

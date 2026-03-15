use std::cell::Cell;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossfire::flavor::Queue;
use libc::c_void;

use super::heap::Heap;
use super::stats::AllocatorStats;

pub type SeqQueue<T> = crossfire::flavor::List<T>;

/// Duration between GC cycles
const GC_DURATION: Duration = Duration::from_millis(1000 * 5);

/// ClashMap with FxHasher
type HeapMap<K, V> = clashmap::ClashMap<K, V, rustc_hash::FxBuildHasher>;

/// Thread-local cache entry. Bypasses ClashMap lookup on the hot path.
#[derive(Clone, Copy)]
struct TlcEntry {
    sheap_id: usize,
    generation: usize,
    heap: *const Heap,
}

impl TlcEntry {
    const fn empty() -> Self {
        Self {
            sheap_id: 0,
            generation: 0,
            heap: std::ptr::null(),
        }
    }
}

// Single TLC slot shared by both fast and slow paths.
thread_local! {
    static TLC: Cell<TlcEntry> = const { Cell::new(TlcEntry::empty()) };
}

pub struct Runtime {
    /// Stats shared down to region layer
    stats: Arc<AllocatorStats>,

    /// HeapMap: sheap_ptr (as usize) → Arc<Heap>
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

    /// Resolves sheap_ptr to a Heap via TLC (fast) or ClashMap (slow).
    /// Creates a new Heap if none exists for this sheap_ptr.
    #[inline]
    fn with_heap<R>(&self, sheap_ptr: *mut c_void, f: impl FnOnce(&Heap) -> R) -> R {
        let sheap_id = sheap_ptr as usize;

        // Fast path: check TLC (Cell::get — Copy, no unsafe needed)
        let tlc = TLC.with(|c| c.get());

        if tlc.sheap_id == sheap_id && !tlc.heap.is_null() {
            let heap = unsafe { &*tlc.heap };

            // Validate generation hasn't changed (purge invalidates TLC)
            if heap.get_generation() == tlc.generation {
                return f(heap);
            }
        }

        // Slow path: ClashMap lookup or insert
        self.with_heap_slow(sheap_id, f)
    }

    #[cold]
    fn with_heap_slow<R>(&self, sheap_id: usize, f: impl FnOnce(&Heap) -> R) -> R {
        let guard = self.pool.entry(sheap_id).or_insert_with(|| {
            Arc::new(Heap::new(
                sheap_id,
                self.gc_queue.clone(),
                self.stats.clone(),
            ))
        });

        let heap: &Heap = &guard;
        let generation = heap.get_generation();

        // Update the SAME TLC slot that with_heap reads from
        TLC.with(|c| {
            c.set(TlcEntry {
                sheap_id,
                generation,
                heap: heap as *const Heap,
            });
        });

        f(heap)
    }

    /// Allocates memory from the scrap heap.
    ///
    /// Ultra-fast path: TLC hit + lock-free bump from hot_region (zero locks).
    /// Fast path: TLC hit + Mutex slow alloc (new region creation).
    /// Cold path: ClashMap lookup + slow alloc.
    #[inline]
    pub fn alloc(&self, sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
        let sheap_id = sheap_ptr as usize;
        let tlc = TLC.with(|c| c.get());

        if tlc.sheap_id == sheap_id && !tlc.heap.is_null() {
            let heap = unsafe { &*tlc.heap };

            if heap.get_generation() == tlc.generation {
                // Ultra-fast: lock-free bump from hot_region
                if let Some(ptr) = heap.try_alloc_fast(size, align) {
                    return ptr;
                }

                // Hot region full: slow path (Mutex, new region)
                return heap.try_alloc_slow(size, align).unwrap_or(null_mut());
            }
        }

        // Cold: ClashMap lookup
        self.alloc_cold(sheap_id, size, align)
    }

    #[cold]
    fn alloc_cold(&self, sheap_id: usize, size: usize, align: usize) -> *mut c_void {
        self.with_heap_slow(sheap_id, |heap| {
            // After ClashMap lookup, try fast path first (hot_region may exist)
            if let Some(ptr) = heap.try_alloc_fast(size, align) {
                return ptr;
            }
            heap.try_alloc_slow(size, align).unwrap_or(null_mut())
        })
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

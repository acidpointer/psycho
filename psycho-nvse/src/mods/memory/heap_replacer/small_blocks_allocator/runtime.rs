use std::cell::Cell;
use std::ptr::null_mut;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use libc::c_void;
use libmimalloc::heap::MiHeap;

use super::heap::Heap;
use super::stats::AllocatorStats;
use super::ticker::Ticker;

/// Duration between GC cycles
const GC_DURATION: Duration = Duration::from_secs(1);

type HeapMap<K, V> = clashmap::ClashMap<K, V, rustc_hash::FxBuildHasher>;

thread_local! {
    /// Each thread keeps a safe, strong reference to the last Heap it used.
    /// This ensures the Heap cannot be dropped while this thread is using it.
    static LAST_HEAP: Cell<(usize, *const Heap)> = const { Cell::new((0, std::ptr::null())) };
}

/// Allocator runtime
///
/// Basically, this struct controls all background activities
/// of allocator business logic, such as ticks and garbage
/// collection.
/// Also here we instantiate statistics object, mi heap and
/// `ShardPool`, so we get straightforward inheritance.
pub struct Runtime {
    /// Who will count your ticks? It's ticker!
    ticker: Arc<Ticker>,

    /// Global generation counter
    global_generation: AtomicUsize,

    /// Stats will record all necessary statistics
    /// # Note
    /// AllocatorStats shared deeply to region layer
    stats: Arc<AllocatorStats>,

    /// MiHeap used as backend allocator
    mi_heap: Arc<MiHeap>,

    /// `ShardPool` is special storage for shards
    pool: Arc<HeapMap<usize, Arc<Heap>>>,

    /// Control flag for garbage collector
    gc_run: Arc<AtomicBool>,

    /// Garbage collector thread handle
    gc_handle: Option<JoinHandle<()>>,
}

impl Runtime {
    /// Instantiate allocator runtime
    /// # Background activities:
    /// * `Ticker` - starts tick counter thread
    /// * `gc` - starts garbage collector thread
    pub fn new() -> Self {
        let gc_run = Arc::new(AtomicBool::new(true));

        let mut instance = Self {
            global_generation: AtomicUsize::new(0),
            ticker: Arc::new(Ticker::new()),
            stats: Arc::new(AllocatorStats::new()),
            mi_heap: Arc::new(MiHeap::new()),
            pool: Arc::new(HeapMap::default()),
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
        let ticker = self.ticker.clone();
        let gc_handle = thread::spawn(move || {
            loop {
                thread::sleep(GC_DURATION);

                let is_run = gc_run.load(std::sync::atomic::Ordering::Acquire);

                if !is_run {
                    return;
                }

                let current_tick = ticker.get_current_tick();
                let curr_mem = stats.get_total_alloc_mem();

                log::info!(
                    "[STATS] [tick={}] Memory usage: {}Mb ({}Kb)",
                    current_tick,
                    curr_mem / 1024 / 1024,
                    curr_mem / 1024
                );
                let to_remove: Vec<usize> = pool
                    .iter()
                    .filter_map(|r| {
                        if r.value().is_idle() {
                            Some(*r.key())
                        } else {
                            None
                        }
                    })
                    .collect();
                for sheap_id in to_remove {
                    if let Some(heap_ref) = pool.get(&sheap_id) {
                        heap_ref.purge();
                        log::info!("[GC] [sheap_id={:X}] Heap purged (idle)", sheap_id,);
                    }
                }
            }
        });

        self.gc_handle = Some(gc_handle);
    }

    #[inline]
    pub fn alloc(&self, sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
        let sheap_id = sheap_ptr as usize;

        // Very fast path: thread-local cache
        let (cached_gen, last_heap_ptr) = LAST_HEAP.with(|c| c.get());

        if !last_heap_ptr.is_null() {
            let heap_ref = unsafe { &* last_heap_ptr };

            // Validation of generation is absolute required here
            if heap_ref.get_sheap_id() == sheap_id && cached_gen == heap_ref.get_generation() {
                if let Some(ptr) = heap_ref.try_alloc(size, align) {
                    return ptr;
                }
            } else {
                // Poison the cache: It's a stale or wrong heap
                LAST_HEAP.with(|c| c.set((0, std::ptr::null())));
            }
        }

        // Fast path: heap already exists and has capacity.
        // get() holds a shared ClashMap read lock for the duration — multiple
        // threads can proceed concurrently.
        if let Some(heap) = self.pool.get(&sheap_id)
            && let Some(ptr) = heap.try_alloc(size, align)
        {
            // Update TLC
            LAST_HEAP.with(|last_heap| {
                let heap_arc = heap.value();
                let heap_gen = heap_arc.get_generation();
                let stable_ptr = Arc::as_ptr(heap_arc);
                
                last_heap.set((heap_gen, stable_ptr));
            });

            return ptr;
        }

        // Slow path: heap is missing (first use or post-GC) or all regions full.
        let mi_heap = self.mi_heap.clone();
        let stats = self.stats.clone();
        let ticker = self.ticker.clone();

        let heap_ref = self
            .pool
            .entry(sheap_id)
            .or_insert_with(|| {
                let generation = self.global_generation.fetch_add(1, Ordering::Relaxed);

                Arc::new(Heap::new(sheap_id, generation, mi_heap, stats, ticker))
            });

        if let Some(ptr) = heap_ref.try_alloc(size, align) {
            // Update TLC
            LAST_HEAP.with(|last_heap| {
                let heap_arc = heap_ref.value();
                let heap_gen = heap_arc.get_generation();
                let stable_ptr = Arc::as_ptr(heap_arc);
                
                last_heap.set((heap_gen, stable_ptr));
            });

            return ptr;
        }

        log::error!(
            "Runtime: alloc: (sheap_id={:X}) Failed to allocate! NULLPTR returned!",
            sheap_id
        );

        null_mut()
    }

    #[inline]
    pub fn free(&self, sheap_ptr: *mut c_void, ptr: *mut c_void) -> bool {
        if ptr.is_null() {
            return false;
        }

        let sheap_id = sheap_ptr as usize;

        // Very fast path: thread-local cache
        let (cached_gen, last_heap_ptr) = LAST_HEAP.with(|c| c.get());

        if !last_heap_ptr.is_null() {
            let heap_ref = unsafe { &* last_heap_ptr };

            // Validation of generation is absolute required here
            if heap_ref.get_sheap_id() == sheap_id && cached_gen == heap_ref.get_generation() {
                return heap_ref.try_free(ptr);
            } else {
                // Poison the cache: It's a stale or wrong heap
                LAST_HEAP.with(|c| c.set((0, std::ptr::null())));
            }
        }

        // Slow path: get from pool
        if let Some(heap) = self.pool.get(&sheap_id) {
            // Update TLC
            LAST_HEAP.with(|last_heap| {
                let heap_arc = heap.value();
                let heap_gen = heap_arc.get_generation();
                let stable_ptr = Arc::as_ptr(heap_arc);
                
                last_heap.set((heap_gen, stable_ptr));
            });

            return heap.try_free(ptr);
        }

        false
    }

    #[inline]
    pub fn purge(&self, sheap_ptr: *mut c_void) -> bool {
        let sheap_id = sheap_ptr as usize;

        // Very fast path: thread-local cache
        let (cached_gen, last_heap_ptr) = LAST_HEAP.with(|c| c.get());

        if !last_heap_ptr.is_null() {
            let heap_ref = unsafe { &* last_heap_ptr };

            // Validation of generation is absolute required here
            if heap_ref.get_sheap_id() == sheap_id && cached_gen == heap_ref.get_generation() {
                heap_ref.purge();
                return true;
            } else {
                // Poison the cache: It's a stale or wrong heap
                LAST_HEAP.with(|c| c.set((0, std::ptr::null())));
            }
        }

        if let Some(heap) = self.pool.get(&sheap_id) {
            // Update TLC
            LAST_HEAP.with(|last_heap| {
                let heap_arc = heap.value();
                let heap_gen = heap_arc.get_generation();
                let stable_ptr = Arc::as_ptr(heap_arc);
                
                last_heap.set((heap_gen, stable_ptr));
            });

            heap.purge();
            return true;
        }

        false
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.gc_run
            .store(false, std::sync::atomic::Ordering::Release);

        if let Some(handle) = self.gc_handle.take() {
            let _ = handle.join();
        }
    }
}

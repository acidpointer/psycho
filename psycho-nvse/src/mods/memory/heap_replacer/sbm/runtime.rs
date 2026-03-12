use std::cell::Cell;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use libc::c_void;
use libmimalloc::heap::MiHeap;

use super::ticker::Ticker;
use super::heap::Heap;
use super::stats::AllocatorStats;

/// Duration between GC cycles
const GC_DURATION: Duration = Duration::from_millis(777);

/// ClashMap with FxHasher is beast
type HeapMap<K, V> = clashmap::ClashMap<K, V, rustc_hash::FxBuildHasher>;

// Want event faster heap lookups?
// Meet Heap TLC (thread local cache)
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
    /// Global generation counter
    global_generation: AtomicUsize,

    /// Tick counter
    ticker: Arc<Ticker>,

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
    /// and starts garbage collector thread
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

        // initialize AND start garbage collector thread
        instance.init_gc();

        instance
    }

    /// So-called garbage collector (GC)
    /// Goal is simple - find heaps in IDLE state and purge them.
    fn init_gc(&mut self) {
        let gc_run = self.gc_run.clone();
        let pool = self.pool.clone();
        let stats = self.stats.clone();
        let ticker = self.ticker.clone();
        let gc_handle = thread::spawn(move || {
            loop {
                // Check run flag first
                if gc_run.load(Ordering::Acquire) {
                    return;
                }

                thread::sleep(GC_DURATION);

                let current_tick = ticker.get_current_tick();
                let curr_mem = stats.get_total_alloc_mem();
                let heaps_len = pool.len();

                if current_tick.is_multiple_of(8) {
                    log::info!(
                        "[SBM] [tick={}] Memory usage: ({} MB) ({} KB) ({} bytes);  Total heaps amount: {}",
                        current_tick,
                        curr_mem / 1024 / 1024,
                        curr_mem / 1024,
                        curr_mem,
                        heaps_len
                    );
                }

                for heap_ref in pool.iter() {
                    if heap_ref.is_idle() {
                        let purged_amount = heap_ref.checked_purge();

                        if purged_amount > 0 {
                            log::info!(
                                "[GC] [sheap_id={:#x}] Heap purged {} regions (IDLE)",
                                heap_ref.get_sheap_id(),
                                purged_amount
                            );
                        }
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
            let heap_ref = unsafe { &*last_heap_ptr };

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

        let heap_ref = self.pool.entry(sheap_id).or_insert_with(|| {
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

    #[allow(dead_code)]
    #[inline]
    pub fn free(&self, sheap_ptr: *mut c_void, ptr: *mut c_void) {
        if ptr.is_null() {
            return;
        }

        let sheap_id = sheap_ptr as usize;

        // Very fast path: thread-local cache
        let (cached_gen, last_heap_ptr) = LAST_HEAP.with(|c| c.get());

        if !last_heap_ptr.is_null() {
            let heap_ref = unsafe { &*last_heap_ptr };

            // Validation of generation is absolute required here
            if heap_ref.get_sheap_id() == sheap_id && cached_gen == heap_ref.get_generation() {
                heap_ref.free(ptr);
                return;
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

            heap.free(ptr);
        }
    }

    /// Purge heap
    ///
    /// # Arguments
    /// * `sheap_ptr` - sheap pointer, from game
    /// # Returns
    /// `usize` - amount of purged regions
    #[inline]
    pub fn purge(&self, sheap_ptr: *mut c_void) -> usize {
        let sheap_id = sheap_ptr as usize;

        // Very fast path: thread-local cache
        let (cached_gen, last_heap_ptr) = LAST_HEAP.with(|c| c.get());

        if !last_heap_ptr.is_null() {
            let heap_ref = unsafe { &*last_heap_ptr };

            // Validation of generation is absolute required here
            if heap_ref.get_sheap_id() == sheap_id && cached_gen == heap_ref.get_generation() {
                return heap_ref.purge();
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

            return heap.purge();
        }

        0
    }

    /// Singleton: get `Runtime` instance
    pub fn get_instance() -> &'static Self {
        static RT: LazyLock<Runtime> = LazyLock::new(Runtime::new);

        &RT
    }

    /// Get current tick
    #[allow(dead_code)]
    #[inline]
    pub fn get_current_tick(&self) -> u64 {
        self.ticker.get_current_tick()
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

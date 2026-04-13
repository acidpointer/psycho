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

use super::super::mem_stats;

pub type SeqQueue<T> = crossfire::flavor::List<T>;

const GC_DURATION: Duration = Duration::from_millis(1000 * 5);

type HeapMap<K, V> = clashmap::ClashMap<K, V, rustc_hash::FxBuildHasher>;

// ---- Thread-Local Cache ----

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
    pool: Arc<HeapMap<usize, Arc<Heap>>>,
    gc_queue: Arc<SeqQueue<usize>>,
    gc_run: Arc<AtomicBool>,
    gc_handle: Option<JoinHandle<()>>,
}

unsafe impl Send for Runtime {}
unsafe impl Sync for Runtime {}

impl Runtime {
    pub fn new() -> Self {
        let gc_run = Arc::new(AtomicBool::new(true));

        let mut instance = Self {
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
        let gc_queue = self.gc_queue.clone();

        let gc_handle = thread::spawn(move || {
            loop {
                if !gc_run.load(Ordering::Acquire) {
                    return;
                }

                thread::sleep(GC_DURATION);

                let sbm2_mem = mem_stats::global().sbm2_allocated();
                let heaps_len = pool.len();
                log::info!(
                    "[SBM] Memory: {}MB ({}KB); Heaps: {}",
                    sbm2_mem / 1024 / 1024,
                    sbm2_mem / 1024,
                    heaps_len,
                );

                while let Some(sheap_id) = gc_queue.pop() {
                    if let Some(heap) = pool.get(&sheap_id) {
                        let purged = heap.checked_purge();
                        if purged > 0 {
                            log::trace!(
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

    #[cold]
    fn get_or_create_heap(&self, sheap_id: usize) -> Arc<Heap> {
        let gc_queue = &self.gc_queue;
        let guard = self.pool.entry(sheap_id).or_insert_with(|| {
            Arc::new(Heap::new(sheap_id, Arc::clone(gc_queue)))
        });
        Arc::clone(&guard)
    }

    #[inline]
    fn with_heap<R>(&self, sheap_ptr: *mut c_void, f: impl FnOnce(&Heap) -> R) -> R {
        let sheap_id = sheap_ptr as usize;
        let tlc = TLC.with(|c| c.get());

        if tlc.sheap_id == sheap_id && !tlc.heap.is_null() {
            let heap = unsafe { &*tlc.heap };
            if heap.get_generation() == tlc.generation {
                return f(heap);
            }
        }

        self.with_heap_slow(sheap_id, f)
    }

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

    #[inline]
    pub fn alloc(&self, sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
        let sheap_id = sheap_ptr as usize;
        let tlc = TLC.with(|c| c.get());

        if tlc.sheap_id == sheap_id && !tlc.heap.is_null() {
            let heap = unsafe { &*tlc.heap };

            if heap.get_generation() == tlc.generation {
                if !tlc.region.is_null()
                    && let Some(ptr) = unsafe { heap.try_alloc_fast(tlc.region, size, align) } {
                        return ptr;
                    }
                return self.alloc_slow(heap, tlc, size, align);
            }
        }

        self.alloc_cold(sheap_id, size, align)
    }

    #[cold]
    fn alloc_slow(&self, heap: &Heap, tlc: TlcEntry, size: usize, align: usize) -> *mut c_void {
        match heap.try_alloc_slow(size, align) {
            Some(ptr) => {
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

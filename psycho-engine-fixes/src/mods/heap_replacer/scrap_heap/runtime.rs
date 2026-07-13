use std::cell::Cell;
use std::collections::HashMap;
use std::ptr::{self, null_mut};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crossfire::flavor::Queue;
use libc::c_void;
use libpsycho::common::helpers::format_bytes;
use parking_lot::{Mutex, RwLock};
use rustc_hash::FxBuildHasher;

use super::heap::Heap;
use super::heap::REGION_SIZE;
use super::region::Region;

use super::super::mem_stats;

pub type SeqQueue<T> = crossfire::flavor::List<T>;

const GC_DURATION: Duration = Duration::from_millis(1000 * 5);
const SUMMARY_INTERVAL: Duration = Duration::from_secs(60);
const PEAK_LOG_STEP: usize = 4 * 1024 * 1024;
const IDENTITY_LOG_STEP: usize = 16;
const EMERGENCY_REGION_COUNT: usize = 8;

type HeapMap<K, V> = RwLock<HashMap<K, V, FxBuildHasher>>;

#[derive(Default)]
pub struct ScrapSnapshot {
    pub live_bytes: usize,
    pub identities: usize,
    pub active_identities: usize,
    pub regions: usize,
    pub live_allocs: usize,
}

#[derive(Default)]
struct GcCycle {
    queued: usize,
    purged_identities: usize,
    purged_regions: usize,
}

struct ScrapLogState {
    last_summary: Instant,
    logged_peak: usize,
    last_identities: usize,
    was_active: bool,
}

impl ScrapLogState {
    fn new() -> Self {
        Self {
            last_summary: Instant::now(),
            logged_peak: 0,
            last_identities: 0,
            was_active: false,
        }
    }

    fn observe(&mut self, snapshot: &ScrapSnapshot, gc: &GcCycle) {
        let active = snapshot.live_bytes > 0 || snapshot.regions > 0;
        let now = Instant::now();
        let new_peak = snapshot.live_bytes > self.logged_peak + PEAK_LOG_STEP;
        let identity_growth =
            active && snapshot.identities >= self.last_identities.saturating_add(IDENTITY_LOG_STEP);
        let periodic = active && now.duration_since(self.last_summary) >= SUMMARY_INTERVAL;
        let state_change = active != self.was_active;

        if state_change || new_peak || identity_growth || periodic {
            let peak = self.logged_peak.max(snapshot.live_bytes);
            log::info!(
                "[scrap_heap] live={} peak={} ids={} active_ids={} regions={} live_allocs={} gc_queued={} purged_ids={} purged_regions={}",
                format_bytes(snapshot.live_bytes),
                format_bytes(peak),
                snapshot.identities,
                snapshot.active_identities,
                snapshot.regions,
                snapshot.live_allocs,
                gc.queued,
                gc.purged_identities,
                gc.purged_regions,
            );
            self.last_summary = now;
            self.logged_peak = peak;
            self.last_identities = snapshot.identities;
            self.was_active = active;
        } else if gc.queued > 0 || gc.purged_regions > 0 {
            log::debug!(
                "[scrap_heap] gc queued={} purged_ids={} purged_regions={} live={} ids={}",
                gc.queued,
                gc.purged_identities,
                gc.purged_regions,
                format_bytes(snapshot.live_bytes),
                snapshot.identities,
            );
        }
    }
}

// ---- Thread-Local Cache ----

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
            heap: ptr::null(),
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
    emergency_regions: Mutex<Vec<Region>>,
    emergency_regions_used: AtomicUsize,
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
            emergency_regions: Mutex::new(Self::reserve_emergency_regions()),
            emergency_regions_used: AtomicUsize::new(0),
        };

        instance.init_gc();
        instance
    }

    fn reserve_emergency_regions() -> Vec<Region> {
        let mut regions = Vec::with_capacity(EMERGENCY_REGION_COUNT);
        for _ in 0..EMERGENCY_REGION_COUNT {
            let Some(region) = Region::new_emergency(REGION_SIZE) else {
                break;
            };
            regions.push(region);
        }

        if regions.is_empty() {
            log::warn!("[scrap_heap] Emergency reserve unavailable");
        } else {
            log::info!(
                "[scrap_heap] Emergency reserve ready: {}KB in {} regions",
                regions.len() * REGION_SIZE / 1024,
                regions.len(),
            );
        }

        regions
    }

    fn take_emergency_region(&self, capacity: usize) -> Option<Box<Region>> {
        if capacity > REGION_SIZE {
            return None;
        }

        let mut regions = self.emergency_regions.lock();
        // HeapState publishes Region addresses, so establish the final stable
        // address before handing this reserve to a heap.
        let region = regions.pop().map(Box::new);
        let remaining = regions.len();
        drop(regions);

        if region.is_some() {
            let used = self.emergency_regions_used.fetch_add(1, Ordering::Relaxed) + 1;
            log::warn!(
                "[scrap_heap] using emergency reserve region: used={} remaining={}",
                used,
                remaining,
            );
        }

        region
    }

    fn init_gc(&mut self) {
        let gc_run = self.gc_run.clone();
        let pool = self.pool.clone();
        let gc_queue = self.gc_queue.clone();

        let gc_handle = thread::spawn(move || {
            let mut log_state = ScrapLogState::new();

            loop {
                if !gc_run.load(Ordering::Acquire) {
                    return;
                }

                thread::sleep(GC_DURATION);

                let mut gc = GcCycle::default();
                while let Some(sheap_id) = gc_queue.pop() {
                    gc.queued += 1;
                    let heap = pool.read().get(&sheap_id).cloned();
                    if let Some(heap) = heap {
                        let purged = heap.checked_purge();
                        if purged > 0 {
                            gc.purged_identities += 1;
                            gc.purged_regions += purged;
                        }
                    }
                }

                let snapshot = Self::snapshot(&pool);
                log_state.observe(&snapshot, &gc);
            }
        });

        self.gc_handle = Some(gc_handle);
    }

    fn snapshot(pool: &HeapMap<usize, Arc<Heap>>) -> ScrapSnapshot {
        let pool = pool.read();
        let mut snapshot = ScrapSnapshot {
            live_bytes: mem_stats::global().scrap_heap_allocated() as usize,
            identities: pool.len(),
            ..ScrapSnapshot::default()
        };

        for heap in pool.values() {
            let regions = heap.region_count();
            if regions > 0 {
                snapshot.active_identities += 1;
                snapshot.regions += regions;
                snapshot.live_allocs = snapshot.live_allocs.saturating_add(heap.alloc_count());
            }
        }

        snapshot
    }

    pub fn current_snapshot(&self) -> ScrapSnapshot {
        Self::snapshot(&self.pool)
    }

    #[cold]
    fn get_or_create_heap(&self, sheap_id: usize) -> Arc<Heap> {
        if let Some(heap) = self.pool.read().get(&sheap_id).cloned() {
            return heap;
        }

        let gc_queue = &self.gc_queue;
        let mut pool = self.pool.write();
        Arc::clone(
            pool.entry(sheap_id)
                .or_insert_with(|| Arc::new(Heap::new(sheap_id, Arc::clone(gc_queue)))),
        )
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
                return self.alloc_cached(heap, size, align);
            }
        }

        self.alloc_cold(sheap_id, size, align)
    }

    fn alloc_cached(&self, heap: &Heap, size: usize, align: usize) -> *mut c_void {
        match heap.try_alloc_slow_with_reserved(size, align, |capacity| {
            self.take_emergency_region(capacity)
        }) {
            Some(ptr) => ptr,
            None => null_mut(),
        }
    }

    #[cold]
    fn alloc_cold(&self, sheap_id: usize, size: usize, align: usize) -> *mut c_void {
        let heap = self.get_or_create_heap(sheap_id);

        match heap.try_alloc_slow_with_reserved(size, align, |capacity| {
            self.take_emergency_region(capacity)
        }) {
            Some(ptr) => {
                let generation = heap.get_generation();
                TLC.with(|c| {
                    c.set(TlcEntry {
                        sheap_id,
                        generation,
                        heap: &*heap as *const Heap,
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

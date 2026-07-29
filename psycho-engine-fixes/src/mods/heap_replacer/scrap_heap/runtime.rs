//! Process-wide coordination for the ScrapHeap replacement.
//!
//! The runtime maps each native ScrapHeap identity to one stable
//! [`Heap`]. Thread-local entries cache a raw pointer to that
//! heap plus its purge generation; the map never removes identities, so the
//! pointer remains valid for the runtime's lifetime. A generation mismatch
//! forces the next operation through the checked lookup path after purge.
//!
//! New standard regions are acquired in this order:
//!
//! 1. lease a slot from the protected reusable reserve;
//! 2. create an exact dynamic `VirtualAlloc` mapping;
//! 3. after a dynamic failure, recheck the reserve once for a slot returned
//!    concurrently.
//!
//! Oversized requests skip the fixed reserve because one slot cannot satisfy
//! them, preserving those slots for standard requests. Only complete backing
//! failure enters the OOM hook, which drains a bounded number of already
//! queued identities and uses
//! `checked_purge`; it never purges a live heap or invokes engine cleanup from
//! the allocating thread.
//!
//! Lock order is runtime map, one heap state, then reserve state. No path holds
//! the reserve mutex while looking up or purging a heap. Existing-region
//! allocation touches neither the reserve nor VAS telemetry. Failure-triggered
//! `VirtualQuery` diagnostics run only on power-of-two dynamic failures.

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
use parking_lot::RwLock;
use rustc_hash::FxBuildHasher;

use crate::mods::heap_replacer::gheap::hitch::{self, Span};

use super::heap::Heap;
use super::heap::REGION_SIZE;
use super::region::{self, Region};
use super::reserve::{RegionReserve, ReserveSnapshot};

use super::super::mem_stats;
use libpsycho::os::windows::winapi::{get_current_thread_id, get_last_error_code, get_tick_count};

/// Unbounded multi-producer queue used for zero-live heap identities.
pub type SeqQueue<T> = crossfire::flavor::List<T>;

// The collector is deliberately asynchronous during normal operation. The OOM
// path may drain the same queue synchronously, but still uses checked_purge.
const GC_DURATION: Duration = Duration::from_millis(1000 * 5);

// Summary thresholds bound log traffic independently of allocation frequency.
const SUMMARY_INTERVAL: Duration = Duration::from_secs(60);
const PEAK_LOG_STEP: usize = 4 * 1024 * 1024;
const IDENTITY_LOG_STEP: usize = 16;

// Recovery work must remain bounded on the allocation thread. Additional
// queued identities stay available for the next retry or normal GC cycle.
const OOM_RECLAIM_LIMIT: usize = 32;

type HeapMap<K, V> = RwLock<HashMap<K, V, FxBuildHasher>>;

/// Diagnostic snapshot of ScrapHeap ownership, reserve health, and OOM state.
///
/// The values are collected from multiple atomics and heap locks; they are
/// individually valid but do not represent one globally atomic instant.
#[derive(Default)]
pub struct ScrapSnapshot {
    /// Bytes in regions currently owned by heaps.
    pub live_bytes: usize,
    /// Heap identities retained in the process-lifetime identity map.
    pub identities: usize,
    /// Identities that currently own at least one region.
    pub active_identities: usize,
    /// Total regions currently owned by all identities.
    pub regions: usize,
    /// Total live allocations across all identities.
    pub live_allocs: usize,
    /// Slots created in the fixed reserve at startup.
    pub reserve_total_regions: usize,
    /// Reserve slots not retired after a protection failure.
    pub reserve_usable_regions: usize,
    /// Reserve slots currently leased to heaps.
    pub reserve_in_use_regions: usize,
    /// Peak number of simultaneously leased reserve slots.
    pub reserve_high_water_regions: usize,
    /// Standard-region requests that exhausted the reserve FIFO.
    pub reserve_misses: usize,
    /// Failed reserve `VirtualProtect` transitions.
    pub reserve_protection_failures: usize,
    /// Reserve slots permanently removed after protection failure.
    pub reserve_retired_regions: usize,
    /// Dynamic region mappings currently owned by heaps.
    pub dynamic_live_regions: usize,
    /// Cumulative successful dynamic mappings.
    pub dynamic_allocations: usize,
    /// Cumulative failed dynamic mapping attempts.
    pub dynamic_failures: usize,
    /// Dynamic failures recovered by the concurrent reserve recheck.
    pub recovered_dynamic_failures: usize,
    /// Bounded queue-drain attempts made by the cold OOM path.
    pub reclaim_attempts: usize,
    /// Regions returned by those bounded reclaim attempts.
    pub reclaimed_regions: usize,
    /// Allocations still failing after all OOM retries.
    pub final_failures: usize,
    /// Win32 thread ID for the latest dynamic mapping failure.
    pub last_failure_thread_id: usize,
    /// Native ScrapHeap identity for the latest dynamic mapping failure.
    pub last_failure_sheap_id: usize,
    /// Payload size requested at the latest dynamic mapping failure.
    pub last_failure_size: usize,
    /// Payload alignment requested at the latest dynamic mapping failure.
    pub last_failure_align: usize,
    /// Region capacity requested at the latest dynamic mapping failure.
    pub last_failure_capacity: usize,
    /// Thread-local Win32 last-error value from the failed mapping.
    pub last_failure_error: usize,
    /// Wrapping process tick count recorded for the latest mapping failure.
    pub last_failure_tick: usize,
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
            log::debug!(
                "[scrap_heap] reserve={}/{}/{} used/usable/total high={} misses={} retired={} protect_fail={} dynamic={}/{} live/total failures={} recovered={} reclaim={}/{} attempts/regions final_fail={}",
                snapshot.reserve_in_use_regions,
                snapshot.reserve_usable_regions,
                snapshot.reserve_total_regions,
                snapshot.reserve_high_water_regions,
                snapshot.reserve_misses,
                snapshot.reserve_retired_regions,
                snapshot.reserve_protection_failures,
                snapshot.dynamic_live_regions,
                snapshot.dynamic_allocations,
                snapshot.dynamic_failures,
                snapshot.recovered_dynamic_failures,
                snapshot.reclaim_attempts,
                snapshot.reclaimed_regions,
                snapshot.final_failures,
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

// These counters are observational. In particular, the last-failure fields
// may come from adjacent concurrent failures; they must not be treated as a
// transactional crash record. The power-of-two log emitted by the failing
// thread is the correlated evidence.
#[derive(Default)]
struct RuntimeMetrics {
    dynamic_failures: AtomicUsize,
    recovered_dynamic_failures: AtomicUsize,
    reclaim_attempts: AtomicUsize,
    reclaimed_regions: AtomicUsize,
    final_failures: AtomicUsize,
    last_failure_thread_id: AtomicUsize,
    last_failure_sheap_id: AtomicUsize,
    last_failure_size: AtomicUsize,
    last_failure_align: AtomicUsize,
    last_failure_capacity: AtomicUsize,
    last_failure_error: AtomicUsize,
    last_failure_tick: AtomicUsize,
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

/// Process-lifetime owner of ScrapHeap identities, backing, GC, and telemetry.
///
/// Hook publication is allowed only after [`Runtime::is_ready`] confirms the
/// reserve. Heap identities are intentionally never removed: their stable
/// addresses make the thread-local raw-pointer cache safe.
pub struct Runtime {
    pool: Arc<HeapMap<usize, Arc<Heap>>>,
    gc_queue: Arc<SeqQueue<usize>>,
    gc_run: Arc<AtomicBool>,
    gc_handle: Option<JoinHandle<()>>,
    reserve: Option<Arc<RegionReserve>>,
    metrics: Arc<RuntimeMetrics>,
    #[cfg(test)]
    force_dynamic_failure: AtomicBool,
}

// Heap and reserve internals provide their own synchronization. The GC handle
// is owned exclusively by Runtime, and the identity map stores stable Arcs.
unsafe impl Send for Runtime {}
unsafe impl Sync for Runtime {}

impl Runtime {
    /// Construct allocator state, establish the mandatory reserve, and start GC.
    ///
    /// Construction still returns a value if reserve creation fails so the
    /// `LazyLock` remains usable for diagnostics. Call [`Runtime::is_ready`]
    /// before publishing hooks; activation rejects an unready runtime.
    pub fn new() -> Self {
        let gc_run = Arc::new(AtomicBool::new(true));
        let reserve = RegionReserve::create();
        let metrics = Arc::new(RuntimeMetrics::default());

        let mut instance = Self {
            pool: Arc::new(HeapMap::default()),
            gc_queue: Arc::new(SeqQueue::new()),
            gc_run: gc_run.clone(),
            gc_handle: None,
            reserve,
            metrics,
            #[cfg(test)]
            force_dynamic_failure: AtomicBool::new(false),
        };

        if let Some(reserve) = &instance.reserve {
            let snapshot = reserve.snapshot();
            log::info!(
                "[scrap_heap] Reusable reserve ready: {}KB in {} regions",
                snapshot.total_regions * REGION_SIZE / 1024,
                snapshot.total_regions,
            );
        } else {
            log::error!("[scrap_heap] Reusable reserve unavailable");
        }

        instance.init_gc();
        instance
    }

    /// Return whether the minimum protected reserve was established.
    pub fn is_ready(&self) -> bool {
        self.reserve.is_some()
    }

    fn init_gc(&mut self) {
        let gc_run = self.gc_run.clone();
        let pool = self.pool.clone();
        let gc_queue = self.gc_queue.clone();
        let reserve = self.reserve.clone();
        let metrics = self.metrics.clone();

        let gc_handle = thread::spawn(move || {
            let mut log_state = ScrapLogState::new();

            loop {
                if !gc_run.load(Ordering::Acquire) {
                    return;
                }

                thread::sleep(GC_DURATION);

                hitch::measure_span(Span::ScrapGc, || {
                    let mut gc = GcCycle::default();
                    // Queue entries are hints, not ownership proof. The heap
                    // rechecks its live count while holding its state lock.
                    while let Some(sheap_id) = gc_queue.pop() {
                        gc.queued += 1;
                        // Do not carry the map guard into checked_purge.
                        let heap = { pool.read().get(&sheap_id).cloned() };
                        if let Some(heap) = heap {
                            let purged = heap.checked_purge();
                            if purged > 0 {
                                gc.purged_identities += 1;
                                gc.purged_regions += purged;
                            }
                        }
                    }

                    let snapshot = Self::snapshot(&pool, reserve.as_ref(), &metrics);
                    log_state.observe(&snapshot, &gc);
                });
            }
        });

        self.gc_handle = Some(gc_handle);
    }

    fn snapshot(
        pool: &HeapMap<usize, Arc<Heap>>,
        reserve: Option<&Arc<RegionReserve>>,
        metrics: &RuntimeMetrics,
    ) -> ScrapSnapshot {
        // Preserve the documented map -> heap/reserve ordering while the
        // identity set is enumerated. Allocation paths never take the map lock
        // while holding a heap or reserve lock.
        let pool = pool.read();
        let reserve = reserve.map_or_else(ReserveSnapshot::default, |reserve| reserve.snapshot());
        let mut snapshot = ScrapSnapshot {
            live_bytes: mem_stats::global().scrap_heap_allocated() as usize,
            identities: pool.len(),
            reserve_total_regions: reserve.total_regions,
            reserve_usable_regions: reserve.usable_regions,
            reserve_in_use_regions: reserve.in_use_regions,
            reserve_high_water_regions: reserve.high_water_regions,
            reserve_misses: reserve.misses,
            reserve_protection_failures: reserve.protection_failures,
            reserve_retired_regions: reserve.retired_regions,
            dynamic_live_regions: region::dynamic_live(),
            dynamic_allocations: region::dynamic_allocations(),
            dynamic_failures: metrics.dynamic_failures.load(Ordering::Relaxed),
            recovered_dynamic_failures: metrics.recovered_dynamic_failures.load(Ordering::Relaxed),
            reclaim_attempts: metrics.reclaim_attempts.load(Ordering::Relaxed),
            reclaimed_regions: metrics.reclaimed_regions.load(Ordering::Relaxed),
            final_failures: metrics.final_failures.load(Ordering::Relaxed),
            last_failure_thread_id: metrics.last_failure_thread_id.load(Ordering::Relaxed),
            last_failure_sheap_id: metrics.last_failure_sheap_id.load(Ordering::Relaxed),
            last_failure_size: metrics.last_failure_size.load(Ordering::Relaxed),
            last_failure_align: metrics.last_failure_align.load(Ordering::Relaxed),
            last_failure_capacity: metrics.last_failure_capacity.load(Ordering::Relaxed),
            last_failure_error: metrics.last_failure_error.load(Ordering::Relaxed),
            last_failure_tick: metrics.last_failure_tick.load(Ordering::Relaxed),
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

    /// Collect a diagnostic snapshot without changing allocator ownership.
    pub fn current_snapshot(&self) -> ScrapSnapshot {
        Self::snapshot(&self.pool, self.reserve.as_ref(), &self.metrics)
    }

    #[cold]
    fn get_or_create_heap(&self, sheap_id: usize) -> Arc<Heap> {
        if let Some(heap) = self.pool.read().get(&sheap_id).cloned() {
            return heap;
        }

        // Recheck with the write lock because another thread may have inserted
        // the same identity after the optimistic read.
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
            // Safe because the pool retains every Arc for Runtime lifetime.
            // A purge changes generation but never frees the Heap object.
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

    /// Allocate a payload for a native ScrapHeap identity.
    ///
    /// `sheap_ptr` is used only as an opaque identity and is never
    /// dereferenced. Returns null after backing acquisition fails; the hook
    /// layer owns bounded recovery and final-failure reporting.
    #[inline]
    pub fn alloc(&self, sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
        let sheap_id = sheap_ptr as usize;
        let tlc = TLC.with(|c| c.get());

        if tlc.sheap_id == sheap_id && !tlc.heap.is_null() {
            // Safe for the same reason as `with_heap`: the map retains the Arc
            // and purge changes only generation and owned region state.
            let heap = unsafe { &*tlc.heap };

            if heap.get_generation() == tlc.generation {
                return self.alloc_cached(heap, size, align);
            }
        }

        self.alloc_cold(sheap_id, size, align)
    }

    fn alloc_cached(&self, heap: &Heap, size: usize, align: usize) -> *mut c_void {
        match heap.try_alloc_slow_with_provider(size, align, |capacity| {
            self.acquire_region(heap.identity(), size, align, capacity)
        }) {
            Some(ptr) => ptr,
            None => null_mut(),
        }
    }

    #[cold]
    fn alloc_cold(&self, sheap_id: usize, size: usize, align: usize) -> *mut c_void {
        let heap = self.get_or_create_heap(sheap_id);

        match heap.try_alloc_slow_with_provider(size, align, |capacity| {
            self.acquire_region(sheap_id, size, align, capacity)
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

    fn acquire_region(
        &self,
        sheap_id: usize,
        size: usize,
        align: usize,
        capacity: usize,
    ) -> Option<Box<Region>> {
        // Standard regions consume the precommitted reserve first. Oversized
        // regions bypass it because fixed slots cannot satisfy them and are
        // reserved for requests that can survive without a new VAS mapping.
        if capacity <= REGION_SIZE
            && let Some(reserve) = &self.reserve
        {
            if let Some(slot) = reserve.acquire() {
                return Some(Box::new(Region::from_reserved(slot)));
            }
            reserve.record_miss();
        }

        if let Some(region) = self.new_dynamic_region(capacity) {
            return Some(Box::new(region));
        }

        // Capture last-error immediately after the failed VirtualAlloc path;
        // later logging and VAS enumeration may overwrite the thread-local
        // Win32 value.
        let error = get_last_error_code();
        let failures = self.record_dynamic_failure(sheap_id, size, align, capacity, error);

        // A slot may have returned while VirtualAlloc was in progress. This
        // single recheck closes that useful race without spinning or blocking
        // another heap indefinitely under VAS pressure.
        if capacity <= REGION_SIZE
            && let Some(reserve) = &self.reserve
            && let Some(slot) = reserve.acquire()
        {
            self.metrics
                .recovered_dynamic_failures
                .fetch_add(1, Ordering::Relaxed);
            if failures.is_power_of_two() {
                log::warn!(
                    "[scrap_heap] dynamic region failure recovered by reserve retry: tid={} heap_id={:#x} size={} align={} capacity={}KB error={} failures={}",
                    get_current_thread_id(),
                    sheap_id,
                    size,
                    align,
                    capacity / 1024,
                    error,
                    failures,
                );
            }
            return Some(Box::new(Region::from_reserved(slot)));
        }

        None
    }

    fn new_dynamic_region(&self, capacity: usize) -> Option<Region> {
        #[cfg(test)]
        if self.force_dynamic_failure.load(Ordering::Relaxed) {
            return None;
        }
        Region::new_dynamic(capacity)
    }

    fn record_dynamic_failure(
        &self,
        sheap_id: usize,
        size: usize,
        align: usize,
        capacity: usize,
        error: u32,
    ) -> usize {
        let thread_id = get_current_thread_id();
        self.metrics
            .last_failure_thread_id
            .store(thread_id as usize, Ordering::Relaxed);
        self.metrics
            .last_failure_sheap_id
            .store(sheap_id, Ordering::Relaxed);
        self.metrics
            .last_failure_size
            .store(size, Ordering::Relaxed);
        self.metrics
            .last_failure_align
            .store(align, Ordering::Relaxed);
        self.metrics
            .last_failure_capacity
            .store(capacity, Ordering::Relaxed);
        self.metrics
            .last_failure_error
            .store(error as usize, Ordering::Relaxed);
        self.metrics
            .last_failure_tick
            .store(get_tick_count() as usize, Ordering::Relaxed);

        let failures = self
            .metrics
            .dynamic_failures
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        if failures.is_power_of_two() {
            // A process-map walk is too expensive for every failed allocator
            // call. Power-of-two gating preserves first-failure evidence and a
            // logarithmic history if failures cascade.
            if let Some(vas) = crate::mods::heap_replacer::gheap::vas::sample() {
                log::warn!(
                    "[scrap_heap] dynamic region allocation failed: tid={} heap_id={:#x} size={} align={} capacity={}KB error={} failures={} free={}MB largest=0x{:08x}+{}MB reserve={}MB commit={}MB private={}MB mapped={}MB image={}MB unknown={}MB regions={}",
                    thread_id,
                    sheap_id,
                    size,
                    align,
                    capacity / 1024,
                    error,
                    failures,
                    vas.total_free / crate::mods::heap_replacer::gheap::vas::MB,
                    vas.largest_base,
                    vas.largest_free / crate::mods::heap_replacer::gheap::vas::MB,
                    vas.total_reserve / crate::mods::heap_replacer::gheap::vas::MB,
                    vas.total_commit / crate::mods::heap_replacer::gheap::vas::MB,
                    vas.commit_private / crate::mods::heap_replacer::gheap::vas::MB,
                    vas.commit_mapped / crate::mods::heap_replacer::gheap::vas::MB,
                    vas.commit_image / crate::mods::heap_replacer::gheap::vas::MB,
                    vas.commit_unknown / crate::mods::heap_replacer::gheap::vas::MB,
                    vas.regions,
                );
            } else {
                log::warn!(
                    "[scrap_heap] dynamic region allocation failed: tid={} heap_id={:#x} size={} align={} capacity={}KB error={} failures={}",
                    thread_id,
                    sheap_id,
                    size,
                    align,
                    capacity / 1024,
                    error,
                    failures,
                );
            }
        }
        failures
    }

    /// Reclaim at most 32 queued, still-empty heap identities.
    ///
    /// This is safe on an arbitrary allocation thread because it only releases
    /// Psycho-owned regions after `checked_purge` revalidates zero live
    /// allocations. It deliberately excludes engine, Havok, IO, and mimalloc
    /// cleanup whose thread ownership cannot be satisfied here.
    pub fn reclaim_queued_regions(&self) -> usize {
        self.metrics
            .reclaim_attempts
            .fetch_add(1, Ordering::Relaxed);
        let mut reclaimed = 0usize;
        for _ in 0..OOM_RECLAIM_LIMIT {
            let Some(sheap_id) = self.gc_queue.pop() else {
                break;
            };
            // Clone the Arc and drop the map guard before taking HeapState,
            // preserving the global lock order and minimizing map contention.
            let heap = { self.pool.read().get(&sheap_id).cloned() };
            if let Some(heap) = heap {
                reclaimed = reclaimed.saturating_add(heap.checked_purge());
            }
        }
        self.metrics
            .reclaimed_regions
            .fetch_add(reclaimed, Ordering::Relaxed);
        reclaimed
    }

    /// Record that the hook exhausted every bounded allocation retry.
    pub fn record_final_failure(&self) {
        self.metrics.final_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Free an exact payload pointer belonging to `sheap_ptr`.
    ///
    /// A null payload is accepted as a no-op. The identity pointer remains
    /// opaque and is not dereferenced.
    #[inline]
    pub fn free(&self, sheap_ptr: *mut c_void, ptr: *mut c_void) {
        if ptr.is_null() {
            return;
        }

        self.with_heap(sheap_ptr, |heap| {
            heap.free(ptr);
        })
    }

    /// Unconditionally purge one identity at a native engine lifetime boundary.
    ///
    /// Returns the number of released regions.
    #[inline]
    pub fn purge(&self, sheap_ptr: *mut c_void) -> usize {
        self.with_heap(sheap_ptr, |heap| heap.purge())
    }

    /// Return the process-wide runtime singleton.
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::{REGION_SIZE, Runtime};

    #[test]
    fn dropped_reserved_region_returns_to_reserve() {
        let runtime = Runtime::new();
        let initial = runtime.reserve.as_ref().unwrap().snapshot();

        let region = runtime
            .acquire_region(0x1234, 64, 8, REGION_SIZE)
            .expect("reserved region");
        assert!(region.is_reserved());
        assert_eq!(
            runtime.reserve.as_ref().unwrap().snapshot().in_use_regions,
            1
        );
        drop(region);

        let after = runtime.reserve.as_ref().unwrap().snapshot();
        assert_eq!(after.usable_regions, initial.usable_regions);
        assert_eq!(after.in_use_regions, 0);
    }

    #[test]
    fn exhausted_reserve_and_dynamic_failure_are_recorded() {
        let runtime = Runtime::new();
        let reserve = runtime.reserve.as_ref().unwrap();
        let mut slots = Vec::new();
        while let Some(slot) = reserve.acquire() {
            slots.push(slot);
        }
        runtime.force_dynamic_failure.store(true, Ordering::Relaxed);

        assert!(
            runtime
                .acquire_region(0x9876, 128, 16, REGION_SIZE)
                .is_none()
        );
        let snapshot = runtime.current_snapshot();
        assert_eq!(snapshot.dynamic_failures, 1);
        assert_eq!(snapshot.last_failure_sheap_id, 0x9876);
        assert_eq!(snapshot.last_failure_size, 128);
        assert_eq!(snapshot.last_failure_align, 16);
        assert_eq!(snapshot.last_failure_capacity, REGION_SIZE);
        assert_ne!(snapshot.last_failure_thread_id, 0);

        drop(slots);
    }

    #[test]
    fn oversized_region_does_not_consume_reserve() {
        let runtime = Runtime::new();
        let before = runtime.reserve.as_ref().unwrap().snapshot();
        let region = runtime
            .acquire_region(0x7777, REGION_SIZE, 16, REGION_SIZE + 4096)
            .unwrap();

        assert!(!region.is_reserved());
        assert_eq!(
            runtime.reserve.as_ref().unwrap().snapshot().in_use_regions,
            before.in_use_regions
        );
    }

    #[test]
    fn bounded_reclaim_returns_zero_live_heap_regions() {
        let runtime = Runtime::new();
        let heap = runtime.get_or_create_heap(0x2468);
        let ptr = heap
            .try_alloc_slow_with_provider(64, 8, |capacity| {
                runtime.acquire_region(0x2468, 64, 8, capacity)
            })
            .unwrap();
        heap.free(ptr);

        assert_eq!(
            runtime.reserve.as_ref().unwrap().snapshot().in_use_regions,
            1
        );
        assert_eq!(runtime.reclaim_queued_regions(), 1);
        assert_eq!(
            runtime.reserve.as_ref().unwrap().snapshot().in_use_regions,
            0
        );
        let snapshot = runtime.current_snapshot();
        assert_eq!(snapshot.reclaim_attempts, 1);
        assert_eq!(snapshot.reclaimed_regions, 1);
    }
}

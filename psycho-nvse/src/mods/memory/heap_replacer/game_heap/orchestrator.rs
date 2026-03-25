//! Central coordinator for all game heap operations.
//!
//! Single source of truth for memory management decisions:
//! allocation, quarantine, OOM recovery, frame lifecycle.
//!
//! Owns the quarantine buffers and main thread detection.
//! Uses (but does not own) game_guard locks and pressure relief.
//!
//! # Thread model
//!
//! | Thread            | Role   | Quarantine behavior        |
//! |-------------------|--------|----------------------------|
//! | Main              | Writer | push to quarantine         |
//! | AI worker (2)     | Reader | mi_free directly           |
//! | BSTaskMgr (2)     | Reader | mi_free directly           |
//!
//! # Frame lifecycle
//!
//! ```text
//! Phase 7  on_pre_ai:    write_lock → drain previous → clear dead set
//! Phase 8  on_ai_start:  set AI_ACTIVE
//! Phase 9  (render)
//! Phase 10 on_mid_frame: rotate quarantine, calibrate pressure, relieve
//! Phase 11 on_ai_join:   clear AI_ACTIVE, deferred unload
//! ```
//!
//! # Quarantine buffer lifecycle
//!
//! ```text
//! Normal gameplay:
//!   on_pre_ai:   drain(previous)           ← mi_free here ONLY
//!   on_mid_frame: swap current↔previous    (NO mi_free!)
//!   next on_pre_ai: drain(previous) = this frame's frees
//!
//! During loading:
//!   on_pre_ai:   drain(previous) only — current accumulates
//!   on_mid_frame: skip rotation (loading)
//!   OOM handler:  blocking write + drain ALL (safety valve)
//!
//! Loading → gameplay:
//!   First post-load frame: NVSE events fire (forms in quarantine ✓)
//!   on_mid_frame: swap current→previous
//!   Next on_pre_ai: drain previous (NVSE events done)
//! ```

use libc::c_void;
use std::cell::Cell;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicUsize, Ordering};

use libmimalloc::{
    mi_collect, mi_is_in_heap_region, mi_malloc_aligned, mi_realloc_aligned, mi_usable_size,
};

use super::engine::{addr, globals};
use super::game_guard;
use super::pressure::PressureRelief;
use super::statics;
use super::texture_cache;
use crate::mods::memory::heap_replacer::heap_validate;

const ALIGN: usize = 16;

// Pressure check interval. Every N allocs, check commit threshold.
const PRESSURE_CHECK_INTERVAL: u32 = 50_000;

thread_local! {
    static ALLOC_COUNTER: Cell<u32> = const { Cell::new(0) };
}

// ===========================================================================
// Thread identity (cached per-thread)
// ===========================================================================

// Cached thread ID result. Initialized once per thread on first access
// via is_main_thread_by_tid() (OS thread ID comparison). After that,
// returns the cached value — single TLS read, same as previous commit.
//
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ThreadRole {
    Unknown = 0,
    Main = 1,
    Worker = 2,
}

thread_local! {
    static THREAD_ROLE: Cell<ThreadRole> = const { Cell::new(ThreadRole::Unknown) };
}

// ===========================================================================
// Quarantine internals
// ===========================================================================

// Quarantine activates on the first frame tick (on_pre_ai). Before that,
// main thread frees go to mi_free directly. This prevents quarantine from
// growing to 1.5GB during the first save load from the main menu (game loop
// hasn't started yet, no drain mechanism running).
static QUARANTINE_ACTIVE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

static QUARANTINE_BYTES: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static QUARANTINE: std::cell::UnsafeCell<Quarantine> =
        const { std::cell::UnsafeCell::new(Quarantine::new()) };
}

struct Quarantine {
    current: Vec<(*mut c_void, usize)>,
    previous: Vec<(*mut c_void, usize)>,
}

unsafe impl Send for Quarantine {}

impl Quarantine {
    const fn new() -> Self {
        Self {
            current: Vec::new(),
            previous: Vec::new(),
        }
    }

    #[inline]
    fn push(&mut self, ptr: *mut c_void) {
        let size = unsafe { mi_usable_size(ptr) };
        QUARANTINE_BYTES.fetch_add(size, Ordering::Relaxed);
        self.current.push((ptr, size));
    }

    /// Swap current↔previous. NEVER calls mi_free.
    fn rotate(&mut self) {
        if !self.previous.is_empty() {
            log::error!(
                "[QUARANTINE] BUG: previous not empty at rotate ({} ptrs, {}MB). \
				 Deferring to next drain.",
                self.previous.len(),
                QUARANTINE_BYTES.load(Ordering::Relaxed) / 1024 / 1024,
            );
            self.previous.append(&mut self.current);
            return;
        }
        std::mem::swap(&mut self.current, &mut self.previous);
    }

    /// Drain previous buffer only. Caller must hold write lock.
    fn drain_previous(&mut self) {
        if self.previous.is_empty() {
            return;
        }
        let count = self.previous.len();
        Self::drain_buf(&mut self.previous);
        log::trace!("[QUARANTINE] Drained previous: {} ptrs", count);
    }

    /// Drain all buffers. Caller must hold write lock.
    fn drain_all(&mut self) {
        let count = self.previous.len() + self.current.len();
        if count == 0 {
            return;
        }
        Self::drain_buf(&mut self.previous);
        Self::drain_buf(&mut self.current);
        log::debug!(
            "[QUARANTINE] Drained all: {} ptrs, {}MB remaining",
            count,
            QUARANTINE_BYTES.load(Ordering::Relaxed) / 1024 / 1024,
        );
    }

    fn drain_buf(buf: &mut Vec<(*mut c_void, usize)>) {
        for (ptr, size) in buf.drain(..) {
            QUARANTINE_BYTES.fetch_sub(size, Ordering::Relaxed);
            unsafe { libmimalloc::mi_free(ptr) };
        }
    }
}

// ===========================================================================
// HeapOrchestrator
// ===========================================================================

pub struct HeapOrchestrator;

impl HeapOrchestrator {
    // =======================================================================
    // Thread identity
    // =======================================================================

    /// Check if current thread is main. Cached per-thread once TES is available.
    ///
    /// Before TES init: returns false without caching (re-checks next call).
    /// After TES init: resolves via OS thread ID, caches permanently.
    /// Cached path: single TLS read (same perf as previous commit).
    #[inline]
    pub fn is_main_thread() -> bool {
        THREAD_ROLE.with(|r| {
            match r.get() {
                ThreadRole::Main => true,
                ThreadRole::Worker => false,
                ThreadRole::Unknown => {
                    // TES not initialized → can't determine thread role.
                    // Return false but DON'T cache — re-check next call.
                    let tes = unsafe { *(super::engine::addr::TES_OBJECT as *const *const u8) };
                    if tes.is_null() {
                        return false;
                    }
                    let is_main = globals::is_main_thread_by_tid();
                    r.set(if is_main { ThreadRole::Main } else { ThreadRole::Worker });
                    is_main
                }
            }
        })
    }

    /// Quarantine byte count (for logging/diagnostics).
    pub fn quarantine_usage() -> usize {
        QUARANTINE_BYTES.load(Ordering::Relaxed)
    }

    // =======================================================================
    // Allocation API
    // =======================================================================

    #[inline]
    pub unsafe fn alloc(size: usize) -> *mut c_void {
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            ALLOC_COUNTER.with(|c| {
                let count = c.get().wrapping_add(1);
                c.set(count);
                if count % PRESSURE_CHECK_INTERVAL == 0
                    && let Some(pr) = PressureRelief::instance()
                {
                    unsafe { pr.check() };
                }
            });
            return ptr;
        }
        unsafe { Self::recover_oom(size) }
    }

    #[inline]
    pub unsafe fn free(ptr: *mut c_void) {
        if ptr.is_null() {
            return;
        }

        if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
            // Main thread + quarantine active: delayed free via quarantine.
            // Before first frame tick: quarantine inactive → mi_free directly
            // (prevents 1.5GB quarantine during first save load from menu).
            if Self::is_main_thread()
                && QUARANTINE_ACTIVE.load(Ordering::Acquire)
            {
                QUARANTINE.with(|q| {
                    let q = unsafe { &mut *q.get() };
                    q.push(ptr);
                });
            } else {
                unsafe { libmimalloc::mi_free(ptr) };
            }
            return;
        }

        // Pre-hook pointer: original trampoline handles SBM arenas.
        if let Ok(orig_free) = statics::GHEAP_FREE_HOOK.original() {
            unsafe { orig_free(addr::HEAP_SINGLETON as *mut c_void, ptr) };
            return;
        }

        unsafe { heap_validate::heap_validated_free(ptr) };
    }

    #[inline]
    pub unsafe fn msize(ptr: *mut c_void) -> usize {
        if ptr.is_null() {
            return 0;
        }

        if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
            return unsafe { mi_usable_size(ptr as *const c_void) };
        }

        if let Ok(orig_msize) = statics::GHEAP_MSIZE_HOOK.original() {
            let size = unsafe { orig_msize(addr::HEAP_SINGLETON as *mut c_void, ptr) };
            if size != 0 {
                return size;
            }
        }

        let size = unsafe { heap_validate::heap_validated_size(ptr as *const c_void) };
        if size != usize::MAX {
            return size;
        }

        0
    }

    #[inline]
    pub unsafe fn realloc(ptr: *mut c_void, new_size: usize) -> *mut c_void {
        if ptr.is_null() {
            return unsafe { Self::alloc(new_size) };
        }

        if new_size == 0 {
            unsafe { Self::free(ptr) };
            return null_mut();
        }

        if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
            let new_ptr = unsafe { mi_realloc_aligned(ptr, new_size, ALIGN) };
            if !new_ptr.is_null() {
                return new_ptr;
            }
            return unsafe { Self::recover_oom(new_size) };
        }

        // Pre-hook pointer: alloc new, copy, free old.
        let old_size = unsafe { Self::msize(ptr) };
        if old_size == 0 {
            return null_mut();
        }

        let new_ptr = unsafe { mi_malloc_aligned(new_size, ALIGN) };
        if !new_ptr.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    ptr as *const u8,
                    new_ptr as *mut u8,
                    old_size.min(new_size),
                );
            }
            unsafe { Self::free(ptr) };
        }
        new_ptr
    }

    // =======================================================================
    // Frame lifecycle
    // =======================================================================

    /// Phase 7 (before AI_START): drain quarantine, clear dead set.
    ///
    /// Acquires WRITE lock — blocks until in-flight readers finish.
    /// Drains previous quarantine buffer (one frame old = safe to free).
    /// Clears texture dead set under same lock.
    pub unsafe fn on_pre_ai() {
        // Activate quarantine on first frame tick. Before this, main thread
        // frees go to mi_free directly (zero quarantine during first load).
        QUARANTINE_ACTIVE.store(true, Ordering::Release);

        game_guard::with_write("on_pre_ai", || {
            QUARANTINE.with(|q| {
                let q = unsafe { &mut *q.get() };
                q.drain_previous();
            });

            texture_cache::clear_dead_set();
        });
    }

    /// Mid-frame (post-render, before AI_JOIN): rotate quarantine, pressure.
    ///
    /// AI threads are STILL ACTIVE — must NOT free any memory here.
    /// Rotates quarantine buffers (swap only, no mi_free).
    /// Calibrates pressure baseline, runs pressure relief.
    pub unsafe fn on_mid_frame() {
        if let Some(pr) = PressureRelief::instance() {
            pr.calibrate_baseline();
            pr.flush_pending_counter_decrement();
        }

        if !globals::is_loading() {
            QUARANTINE.with(|q| {
                let q = unsafe { &mut *q.get() };
                q.rotate();
            });
        }

        if let Some(pr) = PressureRelief::instance() {
            unsafe { pr.relieve() };
        }
    }

    /// AI_START: mark AI threads active.
    pub fn on_ai_start() {
        game_guard::set_ai_active();
    }

    /// AI_JOIN: mark AI threads inactive, run deferred unload.
    pub unsafe fn on_ai_join() {
        game_guard::clear_ai_active();

        if let Some(pr) = PressureRelief::instance() {
            unsafe { pr.run_deferred_unload() };
        }
    }

    /// Whether pressure relief is active (for PDD boost decisions in hooks).
    pub fn is_pressure_active() -> bool {
        PressureRelief::instance().is_some_and(|pr| pr.is_requested())
    }

    // =======================================================================
    // Quarantine flush (used by pressure.rs for aggressive collect)
    // =======================================================================

    /// Flush all quarantine with BLOCKING write lock + mi_collect(true).
    ///
    /// Try to flush quarantine (non-blocking) + mi_collect(true).
    /// Uses try_write — skips drain if readers active.
    pub unsafe fn flush_and_collect() {
        game_guard::with_try_write(|| {
            QUARANTINE.with(|q| {
                let q = unsafe { &mut *q.get() };
                q.drain_all();
            });
        });
        unsafe { mi_collect(true) };
    }

    // =======================================================================
    // OOM recovery
    // =======================================================================

    /// OOM recovery — matches previous commit's exact algorithm.
    ///
    /// Key principles:
    /// - try_write EVERYWHERE (never blocking write — stalls cause VAS loss)
    /// - mi_collect(false) every retry iteration (reclaims thread-local pools)
    /// - run_oom_stages does flush+collect+alloc internally (no VAS gap)
    /// - Single retry loop for ALL threads (500 iterations, ~500ms)
    #[cold]
    unsafe fn recover_oom(size: usize) -> *mut c_void {
        let is_main = Self::is_main_thread();

        log::warn!(
            "[OOM] size={}, thread={}, commit={}MB, quarantine={}MB",
            size,
            if is_main { "main" } else { "worker" },
            libmimalloc::process_info::MiMallocProcessInfo::get().get_current_commit()
                / 1024
                / 1024,
            QUARANTINE_BYTES.load(Ordering::Relaxed) / 1024 / 1024,
        );

        // Stage 1: collect this thread's empty pages (lock-free, instant).
        // Picks up segments freed by other threads via the global pool.
        unsafe { mi_collect(false) };
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            return ptr;
        }

        // Stage 2: flush quarantine (try_write, non-blocking) + force collect.
        unsafe { Self::flush_and_collect() };
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            return ptr;
        }

        // Stage 3 (main thread, AI idle): game's OOM stages 0-8.
        // run_oom_stages flushes + collects + tries alloc internally.
        if is_main && !game_guard::is_ai_active() {
            let ptr = unsafe { globals::run_oom_stages(size) };
            if !ptr.is_null() {
                return ptr;
            }
        }

        // Stage 4: retry loop (all threads, 500 iterations).
        // Sleep(1) gives other threads time to free memory.
        // mi_collect(false) reclaims this thread's retired pages.
        // Halfway: flush quarantine + force collect.
        for attempt in 0..500u32 {
            libpsycho::os::windows::winapi::sleep(1);
            unsafe { mi_collect(false) };
            let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
            if !ptr.is_null() {
                if attempt > 10 {
                    log::info!("[OOM] Recovered after {} retries (size={})", attempt, size);
                }
                return ptr;
            }
            if attempt == 250 {
                unsafe { Self::flush_and_collect() };
            }
        }

        // Stage 5 (main thread, AI idle, NOT loading): HeapCompact with cell unload.
        // Nuclear option — signals stage 5 (FindCellToUnload) which frees entire
        // loaded cells. DANGEROUS: deadlocks during loading/fast travel.
        // Acquire write lock FIRST to prevent races with worker hooks during
        // the cell unload + PDD destruction sequence.
        if is_main && !game_guard::is_ai_active() && !globals::is_loading() {
            log::warn!(
                "[OOM] Stage 5: HeapCompact with cell unload (commit={}MB, quarantine={}MB)",
                libmimalloc::process_info::MiMallocProcessInfo::get().get_current_commit()
                    / 1024 / 1024,
                QUARANTINE_BYTES.load(Ordering::Relaxed) / 1024 / 1024,
            );

            // Signal HeapCompact with cell unload (stages 0-5).
            globals::signal_heap_compact(globals::HeapCompactStage::CellUnload);

            // Run game OOM stages — this triggers the HeapCompact dispatcher
            // which processes stages 0-5 including FindCellToUnload.
            unsafe { globals::run_oom_stages(size) };

            // Flush under write lock: cell unload freed objects → quarantine.
            // Write lock ensures no worker reads freed memory during drain.
            game_guard::with_write("oom_cell_unload", || {
                QUARANTINE.with(|q| {
                    let q = unsafe { &mut *q.get() };
                    q.drain_all();
                });
            });
            unsafe { mi_collect(true) };

            let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
            if !ptr.is_null() {
                log::info!("[OOM] Recovered via cell unload (size={})", size);
                return ptr;
            }
        }

        Self::oom_failed(size)
    }

    #[cold]
    fn oom_failed(size: usize) -> *mut c_void {
        let info = libmimalloc::process_info::MiMallocProcessInfo::get();
        log::error!(
            "[OOM] FAILED: size={}, commit={}MB, quarantine={}MB, RSS={}MB",
            size,
            info.get_current_commit() / 1024 / 1024,
            QUARANTINE_BYTES.load(Ordering::Relaxed) / 1024 / 1024,
            info.get_current_rss() / 1024 / 1024,
        );
        null_mut()
    }
}

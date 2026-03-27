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
//! Phase 6  (HeapCompact)  PDD processes queues
//! Phase 7  on_pre_ai:     write_lock → drain_old → clear dead set
//! Phase 8  on_ai_start:   set AI_ACTIVE
//! Phase 9  (render)
//! Phase 10 on_mid_frame:  mark_frame_boundary, calibrate pressure, relieve
//! Phase 11 on_ai_join:    clear AI_ACTIVE, deferred unload, cell unload
//! ```
//!
//! # Quarantine — epoch-based reclamation (2-epoch grace period)
//!
//! ```text
//! Each frame = one epoch. Objects freed in epoch N are safe to
//! reclaim only after all consumers have passed epoch N+2.
//!
//! Push (gheap_free): append to VecDeque (NO mi_free)
//!
//! Epoch advance (on_mid_frame, no lock, SKIP during loading):
//!   retire_cursor = drain_cursor   (epoch N-1 → reclaimable)
//!   drain_cursor  = buf.len()      (epoch N   → retiring)
//!
//! Per-frame drain (on_pre_ai, write lock):
//!   1. free entries 0..retire_cursor (2+ epochs old)
//!   2. if still > 512MB cap: evict oldest
//!
//! Emergency drain (OOM, write lock):
//!   drain ALL entries including recent
//! ```

use libc::c_void;
use std::cell::Cell;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

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
// Watchdog — background thread for memory monitoring
// ===========================================================================

/// Signal from watchdog to main thread: how many cells to unload.
/// 0 = no action needed. Read + cleared by on_pre_ai.
static WATCHDOG_CELL_UNLOAD: AtomicU8 = AtomicU8::new(0);

/// Emergency cleanup signal from worker OOM → main thread alloc.
/// When a worker can't allocate, it sets this flag. The main thread's
/// next alloc checks it and runs cell unload + quarantine flush inline.
/// This works during loading because the main thread IS allocating
/// (loading objects, textures, models go through gheap_alloc).
pub static EMERGENCY_CLEANUP: AtomicBool = AtomicBool::new(false);

/// Watchdog check interval. 200ms for responsive loading detection.
/// Cell unload has its own memory-based cooldown so frequent checks
/// don't cause continuous unloading.
const WATCHDOG_INTERVAL_MS: u64 = 200;

/// Post-load cooldown: timestamp (elapsed_ms) until which game cleanup
/// functions must NOT be called. Set by on_ai_join when loading is
/// detected, checked by on_ai_join AND recover_oom.
///
/// After loading ends, the game does post-load init (Havok restart,
/// scene graph rebuild, NPC setup, NVSE events). Calling game cleanup
/// (OOM stages, HeapCompact, cell unload) during this window corrupts
/// game state — frozen enemies, broken physics, black screen freeze.
static POST_LOAD_UNTIL: AtomicUsize = AtomicUsize::new(0);
const POST_LOAD_COOLDOWN_MS: u64 = 5000;

/// Check if we're in the post-load cooldown window.
fn is_post_load_cooldown() -> bool {
    let until = POST_LOAD_UNTIL.load(Ordering::Relaxed);
    if until == 0 {
        return false;
    }
    let now = libmimalloc::process_info::MiMallocProcessInfo::get().get_elapsed_ms();
    now < until
}

/// Start the watchdog thread. Called once from install.
/// The thread monitors commit growth and signals cell unload when needed.
/// Does NOT touch game state — only reads mimalloc stats and sets atomics.
pub fn start_watchdog() {
    std::thread::Builder::new()
        .name("psycho-watchdog".into())
        .spawn(watchdog_loop)
        .ok();
}

fn watchdog_loop() {
    use libpsycho::os::windows::winapi;

    log::info!("[WATCHDOG] Started (interval={}ms)", WATCHDOG_INTERVAL_MS);

    // Wait for pressure baseline to be calibrated (first frame tick).
    loop {
        winapi::sleep(WATCHDOG_INTERVAL_MS as u32);
        if PressureRelief::instance().is_some_and(|pr| pr.baseline_commit() > 0) {
            break;
        }
    }

    let mut was_loading = false;

    loop {
        winapi::sleep(WATCHDOG_INTERVAL_MS as u32);

        // Log loading transitions (off main thread, no FPS impact).
        let loading = globals::is_loading();
        if loading != was_loading {
            was_loading = loading;
            let info = libmimalloc::process_info::MiMallocProcessInfo::get();
            if loading {
                log::warn!(
                    "[LOADING] Started: commit={}MB, quarantine={}MB",
                    info.get_current_commit() / 1024 / 1024,
                    QUARANTINE_BYTES.load(Ordering::Relaxed) / 1024 / 1024,
                );
            } else {
                log::warn!(
                    "[LOADING] Ended: commit={}MB, quarantine={}MB",
                    info.get_current_commit() / 1024 / 1024,
                    QUARANTINE_BYTES.load(Ordering::Relaxed) / 1024 / 1024,
                );
            }
        }

        let pr = match PressureRelief::instance() {
            Some(pr) => pr,
            None => continue,
        };

        let baseline = pr.baseline_commit();
        if baseline == 0 {
            continue;
        }

        let info = libmimalloc::process_info::MiMallocProcessInfo::get();
        let commit = info.get_current_commit();
        let growth = commit.saturating_sub(baseline);

        // Thresholds for cell unload signal.
        // High thresholds — only trigger when genuinely near OOM.
        // Low thresholds cause useless cell churn (unload → reload cycle).
        const HIGH: usize = 1000 * 1024 * 1024;
        const CRITICAL: usize = 1200 * 1024 * 1024;

        let cells = if growth >= CRITICAL {
            10u8
        } else if growth >= HIGH {
            5
        } else {
            0
        };

        if cells > 0 {
            // Only signal if no pending request AND cooldown expired.
            // Prevents continuous cell unload that kills FPS.
            let current = WATCHDOG_CELL_UNLOAD.load(Ordering::Relaxed);
            if current == 0 {
                WATCHDOG_CELL_UNLOAD.store(cells, Ordering::Release);
                log::info!(
                    "[WATCHDOG] Cell unload signaled: {} cells (commit={}MB, growth={}MB)",
                    cells,
                    commit / 1024 / 1024,
                    growth / 1024 / 1024,
                );
            }
        }
    }
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
// ===========================================================================
// Quarantine — epoch-based reclamation with 2-epoch grace period
// ===========================================================================
//
// Each game frame is an epoch. Objects freed in epoch N stay as readable
// zombies for 2 full epochs and are reclaimed at epoch N+2. This matches
// the original SBM behavior where freed memory stayed readable until reuse.
//
// Why 2 epochs:
//   Epoch N:   object freed → quarantine push
//   Epoch N+1: NVSE events, actor processing, IO tasks may still read it
//   Epoch N+2: all consumers guaranteed done → safe to mi_free
//
// Two cursors track epoch boundaries in the VecDeque:
//   drain_cursor:  entries before this are 1+ epochs old (retiring)
//   retire_cursor: entries before this are 2+ epochs old (reclaimable)
//
// ALL mi_free happens under write lock (game_guard safety for IO workers):
//
// 1. Per-frame reclaim (on_pre_ai, write lock):
//    Free entries before retire_cursor (2+ epochs old).
//    Then cap eviction if >512MB.
//
// 2. Emergency drain (OOM, write lock):
//    Free ALL entries including recent ones (safety valve).
//
// Push NEVER calls mi_free — just appends to the VecDeque.

// Quarantine activates on the first frame tick (on_pre_ai). Before that,
// main thread frees go to mi_free directly. This prevents quarantine from
// growing during the first save load from the main menu (game loop hasn't
// started yet, no drain mechanism running).
static QUARANTINE_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

static QUARANTINE_BYTES: AtomicUsize = AtomicUsize::new(0);

// Hard cap. Cap eviction triggers when quarantine exceeds this.
// 256MB balances zombie protection with commit pressure.
// Higher = more zombies but inflated commit → bigger Gen queue → CellTransition stall.
// Lower = less commit but shorter zombie window → NVSE cache crashes.
const QUARANTINE_LIMIT: usize = 256 * 1024 * 1024;

// Epoch advance interval in frames. Objects survive at least this many
// frames before becoming reclaimable. 5 frames = ~83ms at 60fps.
// SBM gives "until reuse" protection (hundreds of frames for rare sizes).
// 5 frames covers most NVSE caching patterns (script tokens, form lookups).
const EPOCH_INTERVAL_FRAMES: u32 = 5;

thread_local! {
    static QUARANTINE: std::cell::UnsafeCell<Quarantine> =
        const { std::cell::UnsafeCell::new(Quarantine::new()) };
}

struct Quarantine {
    buf: std::collections::VecDeque<(*mut c_void, usize)>,
    total_bytes: usize,
    /// Entries before drain_cursor are 1+ epochs old (retiring).
    /// Set each epoch by advance_epoch: drain_cursor = buf.len().
    drain_cursor: usize,
    /// Entries before retire_cursor are 2+ epochs old (reclaimable).
    /// Set each epoch by advance_epoch: retire_cursor = prev drain_cursor.
    retire_cursor: usize,
}

unsafe impl Send for Quarantine {}

impl Quarantine {
    const fn new() -> Self {
        Self {
            buf: std::collections::VecDeque::new(),
            total_bytes: 0,
            drain_cursor: 0,
            retire_cursor: 0,
        }
    }

    /// Push a freed pointer. Never calls mi_free.
    #[inline]
    fn push(&mut self, ptr: *mut c_void) {
        let size = unsafe { mi_usable_size(ptr) };
        self.buf.push_back((ptr, size));
        self.total_bytes += size;
        QUARANTINE_BYTES.fetch_add(size, Ordering::Relaxed);
    }

    /// Advance epoch: entries from 1-epoch-old become 2-epoch-old
    /// (reclaimable), current entries become 1-epoch-old (retiring).
    ///
    /// Called from on_mid_frame. SKIP during loading (zombie protection
    /// for NVSE/actor processing across loading transitions).
    fn advance_epoch(&mut self) {
        self.retire_cursor = self.drain_cursor;
        self.drain_cursor = self.buf.len();
    }

    /// Reclaim entries aged through the epoch window, then cap eviction.
    /// Epoch advances every 5 frames → objects survive 5-10 frames minimum.
    /// Cap at 256MB prevents commit inflation during stress.
    /// Caller must hold write lock.
    fn reclaim(&mut self) {
        // 1. Epoch drain: free entries from 2+ epoch advances ago.
        //    With 5-frame interval, this is 10-15 frames of protection.
        let to_free = self.retire_cursor.min(self.buf.len());
        if to_free > 0 {
            for _ in 0..to_free {
                if let Some((ptr, size)) = self.buf.pop_front() {
                    self.total_bytes -= size;
                    QUARANTINE_BYTES.fetch_sub(size, Ordering::Relaxed);
                    unsafe { libmimalloc::mi_free(ptr) };
                }
            }
            self.drain_cursor -= to_free;
            self.retire_cursor = 0;
        }

        // 2. Cap eviction: if still over limit, free oldest entries.
        if self.total_bytes > QUARANTINE_LIMIT {
            let before = self.total_bytes;
            let mut evicted_count: usize = 0;
            while self.total_bytes > QUARANTINE_LIMIT {
                match self.buf.pop_front() {
                    Some((ptr, size)) => {
                        self.total_bytes -= size;
                        QUARANTINE_BYTES.fetch_sub(size, Ordering::Relaxed);
                        unsafe { libmimalloc::mi_free(ptr) };
                        evicted_count += 1;
                    }
                    None => break,
                }
            }
            self.drain_cursor = self.drain_cursor.saturating_sub(evicted_count);
            self.retire_cursor = self.retire_cursor.saturating_sub(evicted_count);
            let evicted = before - self.total_bytes;
            if evicted > 1024 * 1024 {
                log::info!(
                    "[QUARANTINE] Evicted {}MB to cap (now={}MB)",
                    evicted / 1024 / 1024,
                    self.total_bytes / 1024 / 1024,
                );
            }
        }
    }

    /// Drain entries that are 2+ epochs old (reclaimable only).
    /// Preserves current AND retiring epoch — full 2-epoch guarantee.
    /// Safe to call at any phase. Caller must hold write lock.
    fn drain_reclaimable(&mut self) {
        let to_free = self.retire_cursor.min(self.buf.len());
        if to_free == 0 {
            return;
        }
        let before = QUARANTINE_BYTES.load(Ordering::Relaxed);
        for _ in 0..to_free {
            if let Some((ptr, size)) = self.buf.pop_front() {
                self.total_bytes -= size;
                QUARANTINE_BYTES.fetch_sub(size, Ordering::Relaxed);
                unsafe { libmimalloc::mi_free(ptr) };
            }
        }
        self.drain_cursor -= to_free;
        self.retire_cursor = 0;
        let freed = before.saturating_sub(QUARANTINE_BYTES.load(Ordering::Relaxed));
        if freed > 1024 * 1024 {
            log::info!(
                "[QUARANTINE] Drained reclaimable: freed {}MB, remaining {}MB",
                freed / 1024 / 1024,
                self.total_bytes / 1024 / 1024,
            );
        }
    }

    /// Drain entries that are 1+ epochs old (retiring + reclaimable).
    /// Breaks 2-epoch guarantee for retiring entries — OOM escalation only.
    /// WARNING: after advance_epoch, drain_cursor = buf.len(), so this
    /// becomes drain_all. Only safe mid-frame (between Phase 7 and Phase 10)
    /// where drain_cursor reflects the PREVIOUS epoch boundary.
    /// Caller must hold write lock.
    fn drain_retired(&mut self) {
        let to_free = self.drain_cursor.min(self.buf.len());
        if to_free == 0 {
            return;
        }
        let before = QUARANTINE_BYTES.load(Ordering::Relaxed);
        for _ in 0..to_free {
            if let Some((ptr, size)) = self.buf.pop_front() {
                self.total_bytes -= size;
                QUARANTINE_BYTES.fetch_sub(size, Ordering::Relaxed);
                unsafe { libmimalloc::mi_free(ptr) };
            }
        }
        self.drain_cursor = 0;
        self.retire_cursor = 0;
        let freed = before.saturating_sub(QUARANTINE_BYTES.load(Ordering::Relaxed));
        if freed > 1024 * 1024 {
            log::info!(
                "[QUARANTINE] Drained retired: freed {}MB, remaining {}MB",
                freed / 1024 / 1024,
                self.total_bytes / 1024 / 1024,
            );
        }
    }

    /// Nuclear: drain ALL entries including current epoch.
    /// Breaks epoch guarantee — use only when alternative is OOM crash.
    /// Caller must hold write lock.
    fn drain_all(&mut self) {
        let count = self.buf.len();
        if count == 0 {
            return;
        }
        let before = QUARANTINE_BYTES.load(Ordering::Relaxed);
        for (ptr, size) in self.buf.drain(..) {
            QUARANTINE_BYTES.fetch_sub(size, Ordering::Relaxed);
            unsafe { libmimalloc::mi_free(ptr) };
        }
        self.total_bytes = 0;
        self.drain_cursor = 0;
        self.retire_cursor = 0;
        let freed = before.saturating_sub(QUARANTINE_BYTES.load(Ordering::Relaxed));
        if freed > 1024 * 1024 || count > 10_000 {
            log::info!(
                "[QUARANTINE] Drained: {} ptrs, freed {}MB, remaining {}MB",
                count,
                freed / 1024 / 1024,
                QUARANTINE_BYTES.load(Ordering::Relaxed) / 1024 / 1024,
            );
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
                    let is_main = globals::is_main_thread_by_tid();
                    if is_main {
                        // Confirmed main thread — cache permanently.
                        r.set(ThreadRole::Main);
                    } else if QUARANTINE_ACTIVE.load(Ordering::Relaxed) {
                        // Game loop started (on_pre_ai set QUARANTINE_ACTIVE).
                        // TES is fully initialized. Safe to cache Worker.
                        // Before game loop: DON'T cache — main thread might
                        // get false from is_main_thread_by_tid during early init
                        // (TES partially constructed, thread ID field not set).
                        r.set(ThreadRole::Worker);
                    }
                    // Before game loop + not main: return false, don't cache,
                    // re-check next call (~50ns overhead, brief init window).
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
            Self::with_emergency_cleanup(|| unsafe { Self::handle_emergency_cleanup() });

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
            if Self::is_main_thread() {
                Self::with_emergency_cleanup(|| unsafe { Self::handle_emergency_cleanup() });

                if !QUARANTINE_ACTIVE.load(Ordering::Acquire) {
                    // Before first frame tick: mi_free directly.
                    // Prevents 1.5GB quarantine during first save load.
                    unsafe { libmimalloc::mi_free(ptr) };
                } else {
                    // Quarantine (NVSE zombie form protection).
                    // Ring buffer auto-evicts oldest entries when over 512MB
                    // cap, recycling VAS continuously during loading.
                    QUARANTINE.with(|q| {
                        let q = unsafe { &mut *q.get() };
                        q.push(ptr);
                    });
                }
                return;
            }

            // Worker thread: free directly. Thread-local mimalloc heap is safe.
            unsafe { libmimalloc::mi_free(ptr) };
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

        // Use alloc() which has full OOM recovery + CRT fallback.
        let new_ptr = unsafe { Self::alloc(new_size) };
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

    /// Phase 7 (before AI_START): reclaim quarantine entries, clear dead set.
    ///
    /// Acquires WRITE lock — blocks until in-flight readers finish.
    /// Reclaims quarantine entries that have aged through 2 full epochs.
    /// Clears texture dead set.
    pub unsafe fn on_pre_ai() {
        // First call: set main thread ID from here — the ONE place we're
        // 100% certain is the game's main thread (main loop Phase 7 hook).
        // Also activates quarantine. Before this, all frees go to mi_free.
        if !QUARANTINE_ACTIVE.load(Ordering::Relaxed) {
            // Always set main thread ID (needed for is_main_thread checks).
            globals::set_main_thread_id();

            // Only activate quarantine when NOT loading.
            // First save load from menu: game loop runs frames during loading.
            // If we activate quarantine here, 1GB+ of frees go to quarantine
            // instead of mi_free → same OOM we're trying to prevent.
            // After loading ends: next on_pre_ai activates quarantine for gameplay.
            if !globals::is_loading() {
                QUARANTINE_ACTIVE.store(true, Ordering::Release);
            }
        }

        game_guard::with_write("on_pre_ai", || {
            QUARANTINE.with(|q| {
                let q = unsafe { &mut *q.get() };
                q.reclaim();
            });
            texture_cache::clear_dead_set();
        });

        // During loading: discard stale watchdog signals.
        if globals::is_loading() {
            WATCHDOG_CELL_UNLOAD.store(0, Ordering::Relaxed);
            super::engine::cell_unload::take_deferred_request();
        }
    }

    /// Mid-frame (post-render, before AI_JOIN): advance epoch, pressure.
    ///
    /// AI threads are STILL ACTIVE — must NOT free any memory here.
    /// Advances the quarantine epoch (no mi_free, just cursor update).
    /// Calibrates pressure baseline, runs pressure relief.
    pub unsafe fn on_mid_frame() {
        if let Some(pr) = PressureRelief::instance() {
            pr.calibrate_baseline();
            pr.flush_pending_counter_decrement();
        }

        // Advance epoch every EPOCH_INTERVAL_FRAMES frames (not every frame).
        // Objects survive at least 5 frames (~83ms) before becoming
        // reclaimable. This matches SBM's "until reuse" better than
        // 2-frame epoch (too short for NVSE caches) or cap-only
        // (512MB commit inflation → Gen queue stall).
        //
        // SKIP during loading: NVSE plugins cache form pointers across
        // the entire loading transition.
        static FRAME_COUNTER: std::sync::atomic::AtomicU32 =
            std::sync::atomic::AtomicU32::new(0);

        if !globals::is_loading() {
            let frame = FRAME_COUNTER.fetch_add(1, Ordering::Relaxed);
            if frame % EPOCH_INTERVAL_FRAMES == 0 {
                QUARANTINE.with(|q| {
                    let q = unsafe { &mut *q.get() };
                    q.advance_epoch();
                });
            }
        }

        if let Some(pr) = PressureRelief::instance() {
            unsafe { pr.relieve() };
        }
    }

    /// AI_START: mark AI threads active.
    pub fn on_ai_start() {
        game_guard::set_ai_active();
    }

    /// AI_JOIN: mark AI threads inactive, run deferred unload, cell unload.
    ///
    /// This is the ONLY safe place for cell unload — AI idle, between frames.
    /// Cell unload is expensive (IO lock + Havok lock) but runs here where
    /// it doesn't stutter visible frames.
    pub unsafe fn on_ai_join() {
        game_guard::clear_ai_active();

        // Skip ALL game cleanup during loading and post-load cooldown.
        // During loading: deadlock risk (IO lock + Havok lock vs loading thread).
        //   CellTransition handles its own blocking PDD + async flush.
        // Post-load cooldown (5s): game doing Havok restart, scene graph rebuild,
        //   NPC setup, IO task completion. Running destruction_protocol or
        //   deferred_cleanup_small here causes multi-second blocking async flush
        //   processing thousands of completed IO tasks → permanent freeze.
        if globals::is_loading() {
            let info = libmimalloc::process_info::MiMallocProcessInfo::get();
            let until = info.get_elapsed_ms() + POST_LOAD_COOLDOWN_MS as usize;
            POST_LOAD_UNTIL.store(until, Ordering::Relaxed);
            return;
        }

        if is_post_load_cooldown() {
            // Discard all cleanup signals during cooldown.
            if let Some(pr) = PressureRelief::instance() {
                pr.clear_deferred_unload();
            }
            WATCHDOG_CELL_UNLOAD.store(0, Ordering::Relaxed);
            super::engine::cell_unload::take_deferred_request();
            return;
        }

        // Pressure-driven deferred unload (aggressive collect + cell unload).
        // ONLY runs outside loading + post-load cooldown.
        if let Some(pr) = PressureRelief::instance() {
            unsafe { pr.run_deferred_unload() };
        }

        // Watchdog + deferred signals: cell unload with memory-based cooldown.
        static COOLDOWN_COMMIT: AtomicUsize = AtomicUsize::new(0);

        let deferred = super::engine::cell_unload::take_deferred_request();
        let watchdog = WATCHDOG_CELL_UNLOAD.swap(0, Ordering::AcqRel) as usize;
        let max_cells = deferred.max(watchdog);

        if max_cells > 0 {
            // Memory-based cooldown: skip if commit is below what it was
            // after the last unload. Only fire again when memory grows back.
            let cooldown = COOLDOWN_COMMIT.load(Ordering::Relaxed);
            let commit = libmimalloc::process_info::MiMallocProcessInfo::get().get_current_commit();
            if cooldown > 0 && commit < cooldown {
                return; // still in cooldown, commit hasn't grown back
            }

            if let Some(result) = super::engine::cell_unload::execute(max_cells)
                && result.cells > 0
            {
                unsafe { Self::flush_all_and_collect() };
                if let Some(pr) = PressureRelief::instance() {
                    pr.set_pending_counter_decrement();
                }
                // Enter cooldown: don't fire again until commit exceeds
                // what it is NOW. This prevents churn when cells get
                // immediately reloaded.
                let post_commit =
                    libmimalloc::process_info::MiMallocProcessInfo::get().get_current_commit();
                COOLDOWN_COMMIT.store(post_commit, Ordering::Relaxed);
            }
        }
    }

    /// Whether pressure relief is active (for PDD boost decisions in hooks).
    pub fn is_pressure_active() -> bool {
        PressureRelief::instance().is_some_and(|pr| pr.is_requested())
    }

    // =======================================================================
    // Emergency cleanup check (used by alloc/free hot paths)
    // =======================================================================

    /// Check emergency signal. If set AND main thread, clear flag and run `f`.
    /// Workers see the flag but don't act — only main thread clears + runs.
    ///
    /// Hot path: single atomic load (1ns, false 99.99%). Cold path: log + closure.
    #[inline]
    fn with_emergency_cleanup(f: impl FnOnce()) {
        if !EMERGENCY_CLEANUP.load(Ordering::Acquire) {
            return;
        }
        Self::with_emergency_cleanup_cold(f);
    }

    #[cold]
    fn with_emergency_cleanup_cold(f: impl FnOnce()) {
        if Self::is_main_thread() {
            EMERGENCY_CLEANUP.store(false, Ordering::Release);
            log::warn!("[EMERGENCY] Main thread handling cleanup");
            f();
        }
        // Workers: no log spam. They can't help — quarantine is main thread TLS.
        // mi_collect(true) in the OOM retry loop already reclaims cross-thread segments.
    }

    // =======================================================================
    // Emergency cleanup (worker OOM → main thread alloc)
    // =======================================================================

    /// Called from main thread alloc when EMERGENCY_CLEANUP is set.
    /// Runs cell unload + quarantine flush + collect inline.
    /// This is the critical path that saves workers during loading —
    /// the main thread is allocating (loading objects), workers are stuck
    /// waiting for VAS, and our hooks/watchdog can't help.
    #[cold]
    unsafe fn handle_emergency_cleanup() {
        let info = libmimalloc::process_info::MiMallocProcessInfo::get();
        let before = info.get_current_commit();

        log::warn!(
            "[EMERGENCY] Cleanup: commit={}MB, quarantine={}MB",
            before / 1024 / 1024,
            QUARANTINE_BYTES.load(Ordering::Relaxed) / 1024 / 1024,
        );

        // 1. Quarantine drain (retired first, then all) + collect.
        game_guard::with_write("emergency_flush", || {
            QUARANTINE.with(|q| {
                let q = unsafe { &mut *q.get() };
                q.drain_all();
            });
        });
        unsafe { mi_collect(true) };

        let after = libmimalloc::process_info::MiMallocProcessInfo::get().get_current_commit();
        log::warn!(
            "[EMERGENCY] Done: commit {}MB→{}MB (freed {}MB)",
            before / 1024 / 1024,
            after / 1024 / 1024,
            before.saturating_sub(after) / 1024 / 1024,
        );
    }

    // =======================================================================
    // Quarantine flush (used by pressure.rs for aggressive collect)
    // =======================================================================

    /// Safe flush: drain reclaimable entries (2+ epochs old) + mi_collect.
    /// Full 2-epoch guarantee preserved. Safe at ANY phase.
    /// Uses try_write — skips if readers active.
    pub unsafe fn flush_reclaimable_and_collect() {
        game_guard::with_try_write(|| {
            QUARANTINE.with(|q| {
                let q = unsafe { &mut *q.get() };
                q.drain_reclaimable();
            });
        });
        unsafe { mi_collect(true) };
    }

    /// Moderate flush: drain 1+ epoch entries + mi_collect.
    /// Breaks 2-epoch guarantee for retiring entries.
    /// WARNING: only safe mid-frame (Phase 7-10). After advance_epoch
    /// (Phase 10), drain_cursor = buf.len() → this becomes drain_all.
    pub unsafe fn flush_retired_and_collect() {
        game_guard::with_try_write(|| {
            QUARANTINE.with(|q| {
                let q = unsafe { &mut *q.get() };
                q.drain_retired();
            });
        });
        unsafe { mi_collect(true) };
    }

    /// Nuclear flush: drain ALL quarantine + mi_collect.
    /// Breaks epoch guarantee — only when alternative is OOM crash.
    /// Uses try_write — skips if readers active.
    pub unsafe fn flush_all_and_collect() {
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

        // Stage 2: safe flush — drain reclaimable (2+ epochs old).
        // Full epoch guarantee preserved.
        unsafe { Self::flush_reclaimable_and_collect() };
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            return ptr;
        }

        // Stage 3: moderate flush — drain 1+ epoch entries.
        // Breaks 2-epoch guarantee but preserves current epoch.
        // Safe mid-frame (OOM happens during game logic, Phase 7-10,
        // drain_cursor reflects previous epoch boundary).
        unsafe { Self::flush_retired_and_collect() };
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            log::warn!("[OOM] Recovered via retired flush (2-epoch guarantee broken)");
            return ptr;
        }

        // Stage 4: nuclear flush — drain ALL including current epoch.
        // Breaks all guarantees but avoids OOM crash.
        unsafe { Self::flush_all_and_collect() };
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            log::warn!("[OOM] Recovered via nuclear flush (epoch guarantee broken)");
            return ptr;
        }

        // Stage 5 (main thread, AI idle, NOT post-load): game's OOM stages 0-8.
        // run_oom_stages calls game cleanup (texture flush, Havok GC, PDD purge).
        // SKIP during post-load cooldown: game is doing Havok restart, scene graph
        // rebuild, NPC setup. Running cleanup stages here corrupts init state →
        // frozen enemies, broken physics, black screen freeze.
        if is_main && !game_guard::is_ai_active() && !is_post_load_cooldown() {
            let ptr = unsafe { globals::run_oom_stages(size) };
            if !ptr.is_null() {
                return ptr;
            }
        }

        // Signal main thread to run emergency cleanup on its next alloc.
        // During loading, main thread is allocating continuously (loading
        // objects). It will see this flag and flush quarantine + cell unload.
        // This is the ONLY mechanism that works during synchronous loading
        // where hooks/watchdog can't reach the main thread.
        if !is_main {
            EMERGENCY_CLEANUP.store(true, Ordering::Release);
            let tid = libpsycho::os::windows::winapi::get_current_thread_id();
            log::warn!("[OOM] Emergency signaled from worker tid={}", tid);
        }

        // Stage 6: retry loop.
        // Main thread: short (10 × 50ms = 500ms) — longer blocks = frozen game.
        // Workers: longer (200 × 50ms = 10s) — workers can wait for main to free.
        let max_retries: u32 = if is_main { 10 } else { 200 };
        for attempt in 0..max_retries {
            libpsycho::os::windows::winapi::sleep(50);
            unsafe { mi_collect(false) };
            let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
            if !ptr.is_null() {
                if attempt > 0 {
                    log::info!("[OOM] Recovered after {} retries (size={})", attempt, size);
                }
                return ptr;
            }
            if attempt == max_retries / 2 {
                unsafe { Self::flush_all_and_collect() };
            }
        }

        // Stage 7 (main thread, AI idle, NOT loading, NOT post-load):
        // Run game OOM stages 0-8 inline. Includes cell unload (stage 5),
        // full PDD (stage 4), texture flush (stage 1), etc.
        // run_oom_stages executes ALL stages directly — no Phase 6 deferral.
        if is_main
            && !game_guard::is_ai_active()
            && !globals::is_loading()
            && !is_post_load_cooldown()
        {
            log::warn!(
                "[OOM] Stage 7: game cleanup (commit={}MB, quarantine={}MB)",
                libmimalloc::process_info::MiMallocProcessInfo::get().get_current_commit()
                    / 1024
                    / 1024,
                QUARANTINE_BYTES.load(Ordering::Relaxed) / 1024 / 1024,
            );

            unsafe { globals::run_oom_stages(size) };

            // Flush objects freed by game stages.
            game_guard::with_write("oom_game_cleanup", || {
                QUARANTINE.with(|q| {
                    let q = unsafe { &mut *q.get() };
                    q.drain_all();
                });
            });
            unsafe { mi_collect(true) };

            let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
            if !ptr.is_null() {
                log::info!("[OOM] Recovered via game cleanup (size={})", size);
                return ptr;
            }
        }

        // Stage 8: infinite retry — never return NULL.
        unsafe { Self::oom_failed(size) }
    }

    /// Last resort: infinite retry with real memory reclamation.
    ///
    /// The vanilla game's alloc NEVER returns NULL — it loops infinitely
    /// with OOM stages. Returning NULL crashes the game because NO code
    /// path checks for allocation failure.
    ///
    /// mi_collect alone frees ~2MB at best (returns unused pages to OS).
    /// Real memory comes from: quarantine flush, game OOM stages, and
    /// HeapCompact (cell unload + PDD purge). Each retry iteration
    /// escalates through these, matching the vanilla infinite loop.
    #[cold]
    unsafe fn oom_failed(size: usize) -> *mut c_void {
        let is_main = Self::is_main_thread();
        let info = libmimalloc::process_info::MiMallocProcessInfo::get();
        log::error!(
            "[OOM] All stages exhausted: size={}, thread={}, commit={}MB, quarantine={}MB, RSS={}MB",
            size,
            if is_main { "main" } else { "worker" },
            info.get_current_commit() / 1024 / 1024,
            QUARANTINE_BYTES.load(Ordering::Relaxed) / 1024 / 1024,
            info.get_current_rss() / 1024 / 1024,
        );

        // Workers: signal main thread and wait. Workers can't run game
        // cleanup functions. Main thread will flush quarantine + run
        // HeapCompact on its next alloc/frame.
        if !is_main {
            EMERGENCY_CLEANUP.store(true, Ordering::Release);
        }

        let mut attempt: u32 = 0;
        loop {
            // 1. Flush quarantine (nuclear, may have accumulated since last flush).
            unsafe { Self::flush_all_and_collect() };

            let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
            if !ptr.is_null() {
                log::warn!("[OOM] Recovered at attempt {} (size={})", attempt, size);
                return ptr;
            }

            // 2. Main thread: run game cleanup (OOM stages + HeapCompact).
            //    This is the REAL memory reclamation — texture flush, PDD purge,
            //    cell unload. Each game stage frees tens to hundreds of MB.
            //    Skip during loading (deadlock risk) and post-load cooldown
            //    (state corruption). In those cases, sleep and retry —
            //    loading will finish and free memory naturally.
            if is_main && !game_guard::is_ai_active() {
                if !globals::is_loading() && !is_post_load_cooldown() {
                    // Run game OOM stages 0-8 INLINE. This executes:
                    //   Stage 0: ProcessPendingCleanup (BSTreeManager)
                    //   Stage 1-2: texture/menu cleanup
                    //   Stage 3: async flush (try)
                    //   Stage 4: full PDD drain (try) — Gen queue stall risk
                    //   Stage 5: cell unload + full PDD (main thread only)
                    //   Stage 6-8: OOM-specific (sleep, retry)
                    // All inline, no Phase 6 deferral. TRY locks = no deadlock.
                    // Gen queue stall is temporary (one-time drain, then empty).
                    // Do NOT signal_heap_compact — we're stuck in alloc,
                    // Phase 6 never runs, the signal would be wasted.
                    let ptr = unsafe { globals::run_oom_stages(size) };
                    if !ptr.is_null() {
                        log::warn!(
                            "[OOM] Recovered via game cleanup at attempt {} (size={})",
                            attempt, size,
                        );
                        return ptr;
                    }

                    // Flush objects freed by game stages.
                    game_guard::with_write("oom_retry", || {
                        QUARANTINE.with(|q| {
                            let q = unsafe { &mut *q.get() };
                            q.drain_all();
                        });
                    });
                    unsafe { mi_collect(true) };

                    let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
                    if !ptr.is_null() {
                        log::warn!(
                            "[OOM] Recovered post-game-cleanup at attempt {} (size={})",
                            attempt, size,
                        );
                        return ptr;
                    }
                }
            }

            // 3. Sleep to let other threads work (BST completing IO,
            //    workers freeing buffers, main thread frame advancing).
            libpsycho::os::windows::winapi::sleep(100);

            attempt += 1;
            if attempt % 10 == 0 {
                let info = libmimalloc::process_info::MiMallocProcessInfo::get();
                log::error!(
                    "[OOM] Attempt {}: size={}, commit={}MB, quarantine={}MB",
                    attempt, size,
                    info.get_current_commit() / 1024 / 1024,
                    QUARANTINE_BYTES.load(Ordering::Relaxed) / 1024 / 1024,
                );
            }
        }
    }
}

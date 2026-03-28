//! Per-thread double-buffer quarantine for UAF protection.
//!
//! Freed objects stay readable (zombie) until drained. Drain happens ONLY
//! at Phase 7 (AI idle) and ONLY when quarantine exceeds a size threshold.
//! Under the threshold, objects accumulate as zombies indefinitely -- this
//! matches SBM's pool behavior where freed blocks stay readable.
//!
//! # Safety proof
//!
//! UAF requires: thread T reads pointer P while mi_free(P) runs on
//! the main thread. We must show this is impossible for all threads.
//!
//! ## Main thread
//! Main thread IS the drainer. Single-threaded, no self-race.
//!
//! ## AI worker threads (2)
//! Active between AI_START (Phase 8) and AI_JOIN (Phase 11).
//! Hold raw (non-refcounted) pointers to actors, NiNodes, ragdoll bones.
//! These objects were destroyed by PDD -> went to quarantine.
//!
//! Quarantine drain (mi_free) ONLY runs in tick_flush() at Phase 7
//! (hook_per_frame_queue_drain). Phase 7 is BEFORE AI_START at Phase 8.
//! After AI_JOIN from the previous frame, AI threads are idle and hold
//! no pointers. **Safe: no overlap.**
//!
//! INVARIANT: tick_rotate() NEVER calls mi_free. It only swaps buffers.
//! This is critical because rotate runs between render and AI_JOIN
//! (AI still active). If rotate drained, it would UAF.
//!
//! ## BSTaskManagerThread (2)
//! Run continuously. Every object they directly hold is refcounted
//! (task objects: InterlockedCompareExchange state 1->3, FUN_0044dd60
//! does DecRef). PDD only destroys refcount-0 objects -> BST's held
//! objects are never in quarantine. Indirect access through texture
//! cache -> protected by texture_dead_set. **Safe: refcounting + dead set.**
//!
//! # Buffer lifecycle
//!
//! ```text
//! Low pressure (quarantine < threshold):
//!   tick_flush:  skip drain (objects stay as zombies)
//!   tick_rotate: append current onto previous (accumulate)
//!   Result: quarantine grows as a single FIFO. Zero drain overhead.
//!
//! High pressure (quarantine >= threshold):
//!   tick_flush:  drain previous (mi_free here ONLY)
//!   tick_rotate: swap current <-> empty previous
//!   Result: one frame of frees drained per Phase 7.
//!
//! During loading:
//!   tick_flush:  drain previous if over threshold (pre-loading frees, safe)
//!   tick_rotate: skip rotation (loading early return)
//!   Quarantine accumulates in current. OOM handler is safety valve.
//! ```

use libc::c_void;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::game_guard;
use super::texture_cache;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// Minimum quarantine bytes before drain kicks in at Phase 7.
// Under this threshold, previous stays undrained (objects stay as zombies).
// rotate_swap appends current to undrained previous, growing the buffer.
// This avoids per-frame mi_free burst cost during low-pressure gameplay.
const DRAIN_THRESHOLD: usize = 64 * 1024 * 1024;

// Absolute cap. Always drain ALL if quarantine exceeds this.
// Prevents runaway VAS growth during sustained stress.
const DRAIN_CAP: usize = 512 * 1024 * 1024;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Quarantine activates on the first non-loading frame tick (on_pre_ai).
/// Before activation, main thread frees go to mi_free directly. This
/// prevents quarantine from growing during the first save load from the
/// main menu (game loop hasn't started yet).
static QUARANTINE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Total bytes across all quarantine buffers (current + previous).
static QUARANTINE_BYTES: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------
// Per-thread quarantine (main thread only)
// ---------------------------------------------------------------------------

thread_local! {
    static QUARANTINE: std::cell::UnsafeCell<ThreadQuarantine> =
        const { std::cell::UnsafeCell::new(ThreadQuarantine::new()) };
}

struct ThreadQuarantine {
    current: Vec<(*mut c_void, usize)>,
    previous: Vec<(*mut c_void, usize)>,
}

unsafe impl Send for ThreadQuarantine {}

impl ThreadQuarantine {
    const fn new() -> Self {
        Self {
            current: Vec::new(),
            previous: Vec::new(),
        }
    }

    #[inline]
    fn push(&mut self, ptr: *mut c_void) {
        let size = unsafe { libmimalloc::mi_usable_size(ptr) };
        QUARANTINE_BYTES.fetch_add(size, Ordering::Relaxed);
        self.current.push((ptr, size));
    }

    /// Swap current <-> previous. NEVER calls mi_free.
    /// Safe to call during AI execution.
    ///
    /// If previous is non-empty (drain was skipped due to threshold),
    /// appends current onto previous. Objects accumulate as a FIFO
    /// and drain together when threshold is exceeded at next tick_flush.
    fn rotate_swap(&mut self) {
        if !self.previous.is_empty() {
            // Drain was skipped (under threshold). Append current to
            // previous so everything drains together when threshold hits.
            self.previous.append(&mut self.current);
            return;
        }
        std::mem::swap(&mut self.current, &mut self.previous);
    }

    /// Drain previous buffer. ONLY call when AI threads are idle.
    fn flush_previous(&mut self) {
        if self.previous.is_empty() {
            return;
        }
        let count = self.previous.len();
        Self::drain_vec(&mut self.previous);
        if count > 10_000 {
            log::debug!("[QUARANTINE] Flushed previous: {} ptrs", count);
        }
    }

    /// Drain all buffers. ONLY call when AI threads are idle (OOM recovery).
    fn flush_all(&mut self) {
        let count = self.previous.len() + self.current.len();
        if count == 0 {
            return;
        }
        Self::drain_vec(&mut self.previous);
        Self::drain_vec(&mut self.current);
        if count > 1000 {
            log::debug!(
                "[QUARANTINE] Flushed all: {} ptrs, {}MB remaining",
                count,
                QUARANTINE_BYTES.load(Ordering::Relaxed) / 1024 / 1024,
            );
        }
    }

    fn drain_vec(buf: &mut Vec<(*mut c_void, usize)>) {
        for (ptr, size) in buf.drain(..) {
            QUARANTINE_BYTES.fetch_sub(size, Ordering::Relaxed);
            unsafe { libmimalloc::mi_free(ptr) };
        }
    }
}

// ---------------------------------------------------------------------------
// Public API -- state queries
// ---------------------------------------------------------------------------

/// Check if quarantine is activated (first non-loading frame tick).
pub fn is_active() -> bool {
    QUARANTINE_ACTIVE.load(Ordering::Acquire)
}

/// Activate quarantine. Called from on_pre_ai when not loading.
pub fn activate() {
    QUARANTINE_ACTIVE.store(true, Ordering::Release);
}

/// Quarantine byte count (for diagnostics/logging).
pub fn usage() -> usize {
    QUARANTINE_BYTES.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Public API -- free path
// ---------------------------------------------------------------------------

/// Push a freed pointer to quarantine (main thread only).
/// Workers call mi_free directly -- not routed here.
#[inline]
pub fn push(ptr: *mut c_void) {
    QUARANTINE.with(|q| {
        let q = unsafe { &mut *q.get() };
        q.push(ptr);
    });
}

// ---------------------------------------------------------------------------
// Public API -- frame lifecycle
// ---------------------------------------------------------------------------

/// Phase 7 (on_pre_ai): conditionally drain previous buffer under write lock.
///
/// AI threads are idle. This is the ONLY place mi_free runs for
/// quarantined pointers. Also clears the texture dead set while
/// the write lock is held.
///
/// Drain is demand-driven: only when quarantine exceeds DRAIN_THRESHOLD.
/// Under the threshold, objects stay as zombies (readable but logically
/// freed). Zero mi_free overhead during normal low-pressure gameplay.
pub fn tick_flush() {
    let qbytes = QUARANTINE_BYTES.load(Ordering::Relaxed);

    game_guard::with_write("tick_flush", || {
        if qbytes >= DRAIN_CAP {
            // Over absolute cap: drain everything to prevent VAS exhaustion.
            QUARANTINE.with(|q| {
                let q = unsafe { &mut *q.get() };
                q.flush_all();
            });
        } else if qbytes >= DRAIN_THRESHOLD {
            // Over threshold: drain previous to reclaim memory.
            QUARANTINE.with(|q| {
                let q = unsafe { &mut *q.get() };
                q.flush_previous();
            });
        }
        // Under threshold: skip drain. Objects stay as zombies.
        // rotate_swap will append current to undrained previous.

        // Clear dead set AFTER drain, while write lock is still held.
        // During drain: BST's texture_cache_find is blocked (write lock).
        // After drain: dead set entries for drained textures are removed.
        // New entries from this frame's PDD will be re-added by dtor hook.
        texture_cache::clear_dead_set();
    });
}

/// Mid-frame (on_mid_frame): swap buffers. NO mi_free.
///
/// AI threads are STILL ACTIVE -- must NOT free any memory here.
/// During loading: skip rotation so frees accumulate in current.
///
/// If previous wasn't drained (under threshold), appends current onto
/// previous. Objects accumulate until threshold triggers drain.
pub fn tick_rotate() {
    if super::engine::globals::is_loading() {
        return;
    }

    QUARANTINE.with(|q| {
        let q = unsafe { &mut *q.get() };
        q.rotate_swap();
    });
}

// ---------------------------------------------------------------------------
// Public API -- OOM recovery / emergency
// ---------------------------------------------------------------------------

/// Flush ALL quarantine + mi_collect. OOM recovery path.
/// Uses try_write -- non-blocking. Skips if readers active.
pub unsafe fn flush_all_and_collect() {
    game_guard::with_try_write(|| {
        QUARANTINE.with(|q| {
            let q = unsafe { &mut *q.get() };
            q.flush_all();
        });
    });
    unsafe { libmimalloc::mi_collect(true) };
}

/// Emergency flush: blocking write lock + drain all + collect.
/// Called from main thread when EMERGENCY_CLEANUP is set.
/// Blocks until readers finish (microsecond-scoped reads).
pub unsafe fn emergency_flush() {
    let before = QUARANTINE_BYTES.load(Ordering::Relaxed);

    game_guard::with_write("emergency_flush", || {
        QUARANTINE.with(|q| {
            let q = unsafe { &mut *q.get() };
            q.flush_all();
        });
    });
    unsafe { libmimalloc::mi_collect(true) };

    let after = QUARANTINE_BYTES.load(Ordering::Relaxed);
    if before > after + 1024 * 1024 {
        log::info!(
            "[QUARANTINE] Emergency flush: freed {}MB",
            (before - after) / 1024 / 1024,
        );
    }
}

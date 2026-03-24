//! Per-thread quarantine for UAF protection.
//!
//! # Safety proof
//!
//! UAF requires: thread T reads pointer P, while mi_free(P) runs on
//! the main thread. We must show this is impossible for all threads.
//!
//! ## Main thread
//! Main thread IS the drainer. Single-threaded, no self-race.
//!
//! ## AI worker threads (2)
//! Active between AI_START (0x0086ec87) and AI_JOIN (0x0086ee4e).
//! Hold raw (non-refcounted) pointers to actors, NiNodes, ragdoll bones.
//! These objects were destroyed by PDD → went to quarantine.
//!
//! Quarantine drain (mi_free) ONLY runs in tick_flush() at Phase 7
//! (hook_per_frame_queue_drain, address 0x0086eadf). Phase 7 is BEFORE
//! AI_START at Phase 8. After AI_JOIN from the previous frame, AI
//! threads are idle and hold no pointers. **Safe: no overlap.**
//!
//! INVARIANT: rotate_swap() NEVER calls mi_free. It only swaps buffers.
//! This is critical because rotate runs between render and AI_JOIN
//! (AI still active). If rotate drained, it would UAF.
//!
//! ## BSTaskManagerThread (2)
//! Run continuously. Every object they directly hold is refcounted
//! (task objects: InterlockedCompareExchange state 1→3, FUN_0044dd60
//! does DecRef). PDD only destroys refcount-0 objects → BST's held
//! objects are never in quarantine. Indirect access through texture
//! cache → protected by texture_dead_set. **Safe: refcounting + dead set.**
//!
//! ## Loading ceiling flush
//! During loading, quarantine can grow unbounded. Ceiling flush runs
//! in tick_flush() at Phase 7 (AI idle), not in tick_rotate().
//! **Safe: same Phase 7 guarantee.**
//!
//! # Buffer lifecycle
//!
//! ```text
//! Normal gameplay:
//!   Frame N, Phase 7 (tick_flush):  drain(previous)  ← mi_free here ONLY
//!   Frame N, mid-frame (tick_rotate): swap current↔previous (NO mi_free!)
//!   Frame N+1, Phase 7 (tick_flush): drain(previous) = frame N's frees
//!
//! During loading:
//!   tick_flush: NO drain (NVSE needs zombie forms post-load)
//!   tick_rotate: skip rotation (loading early return)
//!   Quarantine accumulates unbounded. OOM handler is safety valve.
//!
//! Loading → gameplay transition:
//!   Frame L+1 (first non-loading): NVSE events fire (forms still in quarantine ✓)
//!   Frame L+1 tick_rotate: swap current↔previous
//!   Frame L+2 tick_flush: drain previous (safe, NVSE events done)
//! ```

use libc::c_void;
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::texture_cache;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Thread identification
// ---------------------------------------------------------------------------

thread_local! {
    static IS_MAIN_THREAD: Cell<bool> = const { Cell::new(false) };
}

pub fn is_main_thread() -> bool {
    IS_MAIN_THREAD.with(|f| f.get())
}

// ---------------------------------------------------------------------------
// Quarantine byte tracking
// ---------------------------------------------------------------------------

static QUARANTINE_BYTES: AtomicUsize = AtomicUsize::new(0);

pub fn get_quarantine_usage() -> usize {
    QUARANTINE_BYTES.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Per-thread quarantine buffer
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

    /// Swap current↔previous. NEVER calls mi_free.
    /// Safe to call during AI execution.
    fn rotate_swap(&mut self) {
        // Previous MUST be empty (drained by tick_flush earlier this frame).
        // If not, we have a bug — but we must NOT drain here (AI is active).
        if !self.previous.is_empty() {
            log::error!(
                "[QUARANTINE] BUG: previous not empty at rotate ({} ptrs, {}MB). \
                 Deferring to next tick_flush.",
                self.previous.len(),
                QUARANTINE_BYTES.load(Ordering::Relaxed) / 1024 / 1024,
            );
            // Append current onto previous instead of swapping.
            // Everything drains at next tick_flush.
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
        Self::drain(&mut self.previous);
        log::trace!("[QUARANTINE] Flushed previous: {} ptrs", count);
    }

    /// Drain all buffers. ONLY call when AI threads are idle.
    fn flush_all(&mut self) {
        let count = self.previous.len() + self.current.len();
        if count == 0 {
            return;
        }
        Self::drain(&mut self.previous);
        Self::drain(&mut self.current);
        log::debug!(
            "[QUARANTINE] Flushed all: {} ptrs, {}MB remaining",
            count,
            QUARANTINE_BYTES.load(Ordering::Relaxed) / 1024 / 1024,
        );
    }

    fn drain(buf: &mut Vec<(*mut c_void, usize)>) {
        for (ptr, size) in buf.drain(..) {
            QUARANTINE_BYTES.fetch_sub(size, Ordering::Relaxed);
            unsafe { libmimalloc::mi_free(ptr) };
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Called from hook_per_frame_queue_drain (Phase 7, before AI_START).
///
/// Acquires WRITE lock, then drains previous buffer (mi_free). The write
/// lock blocks until any in-flight reader (AI hook, BST hook) finishes
/// their current microsecond-scoped call.
///
/// Only drains `previous` — never `current`. During loading, `current`
/// accumulates frees from PDD (old worldspace objects). NVSE fires
/// cell-change events on the first post-load frame and may reference
/// those forms. They must stay readable until NVSE dispatch completes.
/// After loading, tick_rotate swaps current→previous, and the next
/// tick_flush drains them safely.
pub fn tick_flush() {
    // Set IS_MAIN_THREAD here so first-frame flush works correctly.
    // (tick_rotate also sets it, but runs AFTER us in the frame.)
    IS_MAIN_THREAD.with(|f| f.set(true));

    // Acquire write lock -- blocks concurrent readers during drain.
    let _guard = super::destruction_guard::write_lock();

    QUARANTINE.with(|q| {
        let q = unsafe { &mut *q.get() };

        // Always drain previous -- these are frees from BEFORE the current
        // loading screen started. Safe to reclaim: they were already dead
        // when loading began, no NVSE handler references them.
        q.flush_previous();

        // During loading: do NOT flush current. Current accumulates frees
        // from THIS loading screen (PDD destroying old worldspace objects).
        // NVSE fires cell-change events on the first post-load frame and
        // may reference these forms. They must stay as readable zombie
        // memory until after NVSE dispatch completes.
        //
        // After loading: tick_rotate swaps current→previous, then next
        // tick_flush drains previous (by which time NVSE events are done).
    });

    // Clear dead set AFTER drain, while write lock is still held.
    // Dead set entries must persist until AFTER their corresponding
    // quarantine buffer is drained. Clearing here ensures:
    // - During drain: BST's texture_cache_find is blocked (write lock)
    // - After drain: dead set entries for drained textures are removed
    // - New entries from this frame's PDD (Phase 4, before Phase 7)
    //   will be re-added by hook_nisourcetexture_dtor
    texture_cache::clear_dead_set();

    // Write lock dropped here — readers can proceed.
}

/// Called from hook_main_loop_maintenance (between render and AI_JOIN).
///
/// Rotates buffers (swap only, NO mi_free). AI threads are still active,
/// so this MUST NOT free any memory.
pub fn tick_rotate() {
    IS_MAIN_THREAD.with(|f| f.set(true));

    if let Some(pr) = super::pressure::PressureRelief::instance() {
        pr.calibrate_baseline();
        pr.flush_pending_counter_decrement();
    }

    // Dead set cleared in tick_flush (after drain, under write lock).
    // Do NOT clear here — tick_rotate runs between render and AI_JOIN,
    // but quarantine drain happens next frame. Dead entries must persist.

    let loading = super::engine::globals::is_loading();

    if loading {
        // During loading: don't rotate. Frees accumulate in current.
        // Ceiling handled by tick_flush (Phase 7, AI idle).
        return;
    }

    QUARANTINE.with(|q| {
        let q = unsafe { &mut *q.get() };
        q.rotate_swap();
    });
}

/// Free a GameHeap pointer.
///
/// Main thread: quarantine (double-buffer for temporal separation).
/// Worker threads: direct mi_free (mimalloc thread-safe).
#[inline]
pub unsafe fn quarantine_free(ptr: *mut c_void) {
    if IS_MAIN_THREAD.with(|f| f.get()) {
        // Main thread: quarantine for temporal separation between phases.
        QUARANTINE.with(|q| {
            let q = unsafe { &mut *q.get() };
            q.push(ptr);
        });
    } else {
        // Worker thread: free directly. Thread-local mimalloc heap is safe.
        unsafe { libmimalloc::mi_free(ptr) };
    }
}

/// Flush all quarantine on current thread (OOM recovery).
///
/// Uses try_write — always non-blocking. If any reader is active (AI hook
/// or BST hook in progress), returns false. Caller falls through to other
/// recovery strategies (mi_collect, retry loop).
pub unsafe fn flush_current_thread() -> bool {
    let _guard = match super::destruction_guard::try_write_lock() {
        Some(g) => g,
        None => return false,
    };

    QUARANTINE.with(|q| {
        let q = unsafe { &mut *q.get() };
        q.flush_all();
    });

    true
}

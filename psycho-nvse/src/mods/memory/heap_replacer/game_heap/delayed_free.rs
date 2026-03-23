//! Per-thread quarantine for GameHeap frees.
//!
//! Holds freed pointers for exactly one frame cycle before releasing to
//! mimalloc. This covers the gap between object destruction (PDD Phase 4-5)
//! and stale reads (IOManager Phase 3 next frame + NVSE dispatch after
//! inner loop).
//!
//! Main thread only. Worker threads free immediately via mi_free — their
//! frees go to thread-local mimalloc heaps and don't affect main thread
//! reads.
//!
//! Double-buffer design:
//!   tick() at Phase 8: flush `previous`, swap current → previous
//!   During loading: accumulate without flushing (cell transition data
//!   must survive through NVSE dispatch on first gameplay frame)
//!
//! Memory ceiling: if quarantine exceeds CEILING_BYTES during loading,
//! force flush to prevent OOM. This trades UAF risk for crash prevention.

use libc::c_void;
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::destruction_guard::DestructionScope;
use super::texture_cache;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Memory ceiling for quarantine during loading. If exceeded, force flush
/// even during loading screens. 400MB leaves room for D3D9 + new cell data
/// in a 32-bit process with 1.4GB commit ceiling.
const CEILING_BYTES: usize = 400 * 1024 * 1024;

/// Loading flag address. When non-zero, game is in loading screen.
const LOADING_FLAG_PTR: usize = 0x011DEA2B;

// ---------------------------------------------------------------------------
// Thread identification
// ---------------------------------------------------------------------------

thread_local! {
    /// Set to true on the first tick() call. tick() only runs from our
    /// Phase 8 hook which only fires on the main thread.
    static IS_MAIN_THREAD: Cell<bool> = const { Cell::new(false) };
}

/// Check if current thread is the main thread.
#[inline]
pub fn is_main_thread() -> bool {
    IS_MAIN_THREAD.with(|f| f.get())
}

// ---------------------------------------------------------------------------
// Quarantine size tracking
// ---------------------------------------------------------------------------

/// Total bytes in quarantine across both buffers. Used for ceiling check.
static QUARANTINE_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Flag: quarantine exceeded ceiling during loading.
static OVER_CEILING: AtomicBool = AtomicBool::new(false);

/// Get current quarantine memory usage in bytes.
pub fn get_quarantine_bytes() -> usize {
    QUARANTINE_BYTES.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Main thread quarantine (double-buffer)
// ---------------------------------------------------------------------------

thread_local! {
    static QUARANTINE: std::cell::UnsafeCell<MainQuarantine> =
        const { std::cell::UnsafeCell::new(MainQuarantine::new()) };
}

struct MainQuarantine {
    /// Pointers freed this frame. Becomes `previous` on next tick().
    current: Vec<*mut c_void>,
    /// Pointers freed last frame. Flushed on tick().
    previous: Vec<*mut c_void>,
}

unsafe impl Send for MainQuarantine {}

impl MainQuarantine {
    const fn new() -> Self {
        Self {
            current: Vec::new(),
            previous: Vec::new(),
        }
    }

    /// Add a freed pointer to the current frame's buffer.
    #[inline]
    fn push(&mut self, ptr: *mut c_void) {
        let size = unsafe { libmimalloc::mi_usable_size(ptr) };
        QUARANTINE_BYTES.fetch_add(size, Ordering::Relaxed);

        // Check ceiling during loading. If over, set flag for tick().
        if QUARANTINE_BYTES.load(Ordering::Relaxed) > CEILING_BYTES {
            OVER_CEILING.store(true, Ordering::Relaxed);
        }

        self.current.push(ptr);
    }

    /// Rotate buffers WITHOUT flushing. Called from tick_rotate() at Phase 8.
    /// Previous buffer keeps its data until tick_flush() at Phase 4.
    fn rotate_only(&mut self) {
        // If previous still has data (tick_flush hasn't run yet),
        // flush it now to prevent unbounded growth.
        if !self.previous.is_empty() {
            Self::drain(&mut self.previous);
        }

        // Swap: current becomes previous, fresh vec becomes current.
        std::mem::swap(&mut self.current, &mut self.previous);
    }

    /// Flush only the previous buffer. Called from tick_flush() at Phase 4.
    fn flush_previous(&mut self) {
        if self.previous.is_empty() {
            return;
        }
        let _guard = DestructionScope::enter();
        Self::drain(&mut self.previous);
    }

    /// Force flush both buffers. Called during OOM recovery.
    fn flush_all(&mut self) {
        let _guard = DestructionScope::enter();
        Self::drain(&mut self.previous);
        Self::drain(&mut self.current);
    }

    /// Free all pointers in a buffer and update byte counter.
    fn drain(buf: &mut Vec<*mut c_void>) {
        if buf.is_empty() {
            return;
        }
        for ptr in buf.drain(..) {
            let size = unsafe { libmimalloc::mi_usable_size(ptr) };
            QUARANTINE_BYTES.fetch_sub(size, Ordering::Relaxed);
            unsafe { libmimalloc::mi_free(ptr) };
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Phase 8 (post-render): rotate buffers and do per-frame bookkeeping.
///
/// Does NOT flush the previous buffer. The flush happens later at Phase 4
/// (per-frame queue drain) via tick_flush(). This ordering ensures:
/// - AI threads (Phase 6-9) can safely read quarantined data
/// - NVSE dispatch (after inner loop) can safely read quarantined data
/// - IOManager Phase 3 reads are safe (flush hasn't happened yet)
pub fn tick_rotate() {
    // Mark this thread as main thread on first call.
    IS_MAIN_THREAD.with(|f| f.set(true));

    if let Some(pr) = super::pressure::PressureRelief::instance() {
        pr.calibrate_baseline();
        pr.flush_pending_counter_decrement();
    }

    // Clear texture dead set every frame.
    texture_cache::clear_dead_set();

    let loading = unsafe { *(LOADING_FLAG_PTR as *const u8) != 0 };

    QUARANTINE.with(|q| {
        let q = unsafe { &mut *q.get() };

        if loading {
            // Loading screen: don't rotate. Accumulate in current buffer.
            // Cell transition data must survive through NVSE dispatch
            // on the first gameplay frame after loading.
            //
            // Check ceiling to prevent OOM during long loading screens.
            if QUARANTINE_BYTES.load(Ordering::Relaxed) > CEILING_BYTES {
                log::warn!(
                    "[QUARANTINE] Ceiling exceeded ({}MB > {}MB) during loading — flushing",
                    QUARANTINE_BYTES.load(Ordering::Relaxed) / 1024 / 1024,
                    CEILING_BYTES / 1024 / 1024,
                );
                q.flush_all();
            }
            return;
        }

        // Normal gameplay: rotate. Previous buffer will be flushed
        // at the next tick_flush() call (Phase 4).
        q.rotate_only();
    });
}

/// Phase 4 (per-frame queue drain entry): flush the previous buffer.
///
/// Called at the START of hook_per_frame_queue_drain, BEFORE PDD runs.
/// At this point in the frame:
/// - AI threads are idle (joined in Phase 9 of previous frame)
/// - NVSE dispatch completed (fired after previous inner loop)
/// - IOManager Phase 3 completed (earlier this frame)
/// All readers of the previous frame's quarantined data are done.
pub fn tick_flush() {
    if !IS_MAIN_THREAD.with(|f| f.get()) {
        return;
    }

    QUARANTINE.with(|q| {
        let q = unsafe { &mut *q.get() };
        q.flush_previous();
    });
}

/// Free a GameHeap pointer. Main thread: quarantine. Others: mi_free.
///
/// # Safety
/// `ptr` must be a valid mimalloc allocation.
#[inline]
pub unsafe fn quarantine_free(ptr: *mut c_void) {
    if IS_MAIN_THREAD.with(|f| f.get()) {
        // Main thread: defer free to next tick().
        QUARANTINE.with(|q| {
            let q = unsafe { &mut *q.get() };
            q.push(ptr);
        });
    } else {
        // Worker thread: free immediately. Their frees go to thread-local
        // mimalloc heaps and don't interfere with main thread reads.
        unsafe { libmimalloc::mi_free(ptr) };
    }
}

/// Flush all quarantine on the current thread. Called during OOM recovery.
///
/// # Safety
/// Only call when OOM is imminent — bypasses the zombie window.
pub unsafe fn flush_current_thread() {
    if IS_MAIN_THREAD.with(|f| f.get()) {
        QUARANTINE.with(|q| {
            let q = unsafe { &mut *q.get() };
            q.flush_all();
        });
    }
    // Worker threads have no quarantine to flush.
}

/// Get quarantine usage for diagnostics (total bytes).
pub fn get_quarantine_usage() -> usize {
    QUARANTINE_BYTES.load(Ordering::Relaxed)
}

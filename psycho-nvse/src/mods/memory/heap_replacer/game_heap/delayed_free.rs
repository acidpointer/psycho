//! Per-thread quarantine with RwLock-based cross-thread synchronization.
//!
//! Main thread: double-buffer quarantine, rotated at Phase 8, flushed at
//! Phase 4. Drain holds heap WRITE lock to block readers during recycle.
//!
//! Worker threads: try_write on free. If readers active (lock busy),
//! defer to thread-local buffer. Buffer flushed next time lock is free.

use libc::c_void;
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::destruction_guard;
use super::texture_cache;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Quarantine ceiling during loading. Force flush if exceeded.
const CEILING_BYTES: usize = 200 * 1024 * 1024;

/// Loading flag address.
const LOADING_FLAG_PTR: usize = 0x011DEA2B;

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

    fn rotate_only(&mut self) {
        if !self.previous.is_empty() {
            Self::drain(&mut self.previous);
        }
        std::mem::swap(&mut self.current, &mut self.previous);
    }

    fn flush_previous(&mut self) {
        if self.previous.is_empty() {
            return;
        }
        let count = self.previous.len();
        Self::drain(&mut self.previous);
        log::trace!("[QUARANTINE] Flushed previous: {} ptrs", count);
    }

    fn flush_all(&mut self) {
        let count = self.previous.len() + self.current.len();
        if count == 0 {
            return;
        }
        Self::drain(&mut self.previous);
        Self::drain(&mut self.current);
        log::debug!("[QUARANTINE] Flushed all: {} ptrs, {}MB remaining",
            count, QUARANTINE_BYTES.load(Ordering::Relaxed) / 1024 / 1024);
    }

    /// Drain buffer under write lock. Size tracked at push time, not here.
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

/// Phase 8: rotate main thread buffers.
pub fn tick_rotate() {
    IS_MAIN_THREAD.with(|f| f.set(true));

    if let Some(pr) = super::pressure::PressureRelief::instance() {
        pr.calibrate_baseline();
        pr.flush_pending_counter_decrement();
    }

    texture_cache::clear_dead_set();

    let loading = unsafe { *(LOADING_FLAG_PTR as *const u8) != 0 };

    QUARANTINE.with(|q| {
        let q = unsafe { &mut *q.get() };

        if loading {
            if QUARANTINE_BYTES.load(Ordering::Relaxed) > CEILING_BYTES {
                log::warn!(
                    "[QUARANTINE] Ceiling exceeded ({}MB > {}MB) during loading",
                    QUARANTINE_BYTES.load(Ordering::Relaxed) / 1024 / 1024,
                    CEILING_BYTES / 1024 / 1024,
                );
                q.flush_all();
            }
            return;
        }

        q.rotate_only();
    });
}

/// Phase 4: flush previous buffer (under write lock).
pub fn tick_flush() {
    if !IS_MAIN_THREAD.with(|f| f.get()) {
        return;
    }

    QUARANTINE.with(|q| {
        let q = unsafe { &mut *q.get() };
        q.flush_previous();
    });
}

/// Free a GameHeap pointer.
///
/// Main thread: quarantine (double-buffer for same-thread temporal separation
/// between destruction phases and reader phases).
/// Worker threads: direct mi_free. mimalloc is thread-safe — worker frees
/// go to thread-local free lists. Cross-thread page reclamation is handled
/// by mimalloc internally. No RwLock needed for individual frees.
///
/// The RwLock protects BATCH operations only:
/// - PDD (write lock) — destroys many objects atomically
/// - Quarantine drain (write lock) — recycles many pointers atomically
/// - IOManager Phase 3 (read lock) — reads many task results
/// - AI execution (read lock) — reads many physics objects
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
pub unsafe fn flush_current_thread() {
    QUARANTINE.with(|q| {
        let q = unsafe { &mut *q.get() };
        q.flush_all();
    });
}

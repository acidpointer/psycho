//! Delayed free (quarantine) for GameHeap allocations.
//!
//! When enabled, freed GameHeap pointers are held in a per-thread ring buffer
//! for `QUARANTINE_FRAMES` frames before being passed to `mi_free`. This keeps
//! memory contents intact (zombie data), preventing use-after-free crashes from
//! subsystems that hold stale pointers:
//!
//! - IO thread (`BSTaskManagerThread`) holds `QueuedTexture` refs in `LockFreeQueue`
//! - AI threads hold `hkBSHeightFieldShape` refs during raycasting
//! - SpeedTree cache holds cross-frame `BSTreeNode` pointers
//!
//! All game object frees go through `GameHeap::Free` → our `Gheap::free` →
//! this quarantine. Verified by Ghidra audit: no bypass paths exist.
//!
//! # Safety model
//!
//! During normal gameplay (main loop running, `tick()` called every frame):
//! - No bucket limit — ALL frees are quarantined, zero bypass
//! - Stale buckets flushed every frame (3-frame zombie window ≈ 50ms at 60fps)
//!
//! During loading screens (main loop not running, `tick()` not called):
//! - Frame counter is stale — detected by push count without frame advance
//! - After `STALE_PUSH_LIMIT` pushes on a stale frame, bypass to mi_free
//! - AI/IO threads are idle during loading, so no stale pointer risk
//!
//! # Performance
//!
//! - Zero contention: each thread has its own quarantine (thread-local)
//! - One `Vec::push` per free (amortized O(1)), no syscalls on hot path
//! - Proactive flush every frame via `tick()`

use libc::c_void;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Number of frames to hold freed pointers before releasing to mimalloc.
const QUARANTINE_FRAMES: usize = 3;

/// If this many pushes happen on a single thread without a frame advance,
/// we're likely in a loading screen. Start bypassing to mi_free.
/// 50k pushes ≈ 5-15MB of zombie data — safe for 32-bit VA.
/// AI/IO threads are idle during loading, so bypass is safe.
const STALE_PUSH_LIMIT: u32 = 50_000;

// ---------------------------------------------------------------------------
// Frame counter
// ---------------------------------------------------------------------------

/// Global frame counter, incremented once per frame by the main loop hook.
static FRAME_COUNTER: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Public API (called from Gheap)
// ---------------------------------------------------------------------------

/// Advance the frame counter AND proactively flush stale buckets on the
/// calling thread (main thread). Must be called exactly once per frame.
#[inline]
pub fn tick() {
    FRAME_COUNTER.fetch_add(1, Ordering::Relaxed);

    // Proactively flush stale buckets on the main thread.
    QUARANTINE.with(|q| {
        let q = unsafe { &mut *q.get() };
        let frame = FRAME_COUNTER.load(Ordering::Relaxed);
        if let Some(last) = q.last_frame {
            if frame != last {
                q.flush_stale(last, frame);
                q.last_frame = Some(frame);
                q.stale_pushes = 0;
            }
        }
    });
}

/// Quarantine a pointer instead of freeing it immediately.
///
/// # Safety
///
/// `ptr` must be a valid mimalloc allocation.
#[inline]
pub unsafe fn quarantine_free(ptr: *mut c_void) {
    QUARANTINE.with(|q| {
        let q = unsafe { &mut *q.get() };
        q.push(ptr);
    });
}

/// Flush all quarantine buffers on the current thread immediately.
/// Called during OOM recovery to reclaim quarantined memory.
#[inline]
pub unsafe fn flush_current_thread() {
    QUARANTINE.with(|q| {
        let q = unsafe { &mut *q.get() };
        q.flush_all();
    });
}

// ---------------------------------------------------------------------------
// Per-thread quarantine
// ---------------------------------------------------------------------------

thread_local! {
    static QUARANTINE: std::cell::UnsafeCell<Quarantine> =
        const { std::cell::UnsafeCell::new(Quarantine::new()) };
}

struct Quarantine {
    /// Ring buffer: bucket[frame % N] holds pointers freed during that frame.
    buckets: [Vec<*mut c_void>; QUARANTINE_FRAMES],
    /// Last frame number seen by this thread. `None` until first `push`.
    last_frame: Option<u64>,
    /// Number of pushes since the last frame advance on this thread.
    /// Used to detect loading screens (many pushes, no frame tick).
    stale_pushes: u32,
}

unsafe impl Send for Quarantine {}

impl Quarantine {
    const fn new() -> Self {
        Self {
            buckets: [const { Vec::new() }; QUARANTINE_FRAMES],
            last_frame: None,
            stale_pushes: 0,
        }
    }

    #[inline]
    fn push(&mut self, ptr: *mut c_void) {
        let frame = FRAME_COUNTER.load(Ordering::Relaxed);

        match self.last_frame {
            None => {
                self.last_frame = Some(frame);
                self.stale_pushes = 0;
            }
            Some(last) if frame != last => {
                // Frame advanced — flush old buckets, reset stale counter.
                self.flush_stale(last, frame);
                self.last_frame = Some(frame);
                self.stale_pushes = 0;
            }
            _ => {}
        }

        // Loading screen detection: if the frame counter hasn't advanced
        // after many pushes, the main loop isn't running. AI/IO threads
        // are idle during loading — bypass quarantine to prevent unbounded
        // growth. No syscalls — just a counter comparison.
        self.stale_pushes += 1;
        if self.stale_pushes > STALE_PUSH_LIMIT {
            unsafe { libmimalloc::mi_free(ptr) };
            return;
        }

        let idx = (frame as usize) % QUARANTINE_FRAMES;
        self.buckets[idx].push(ptr);
    }

    fn flush_stale(&mut self, last_frame: u64, current_frame: u64) {
        let elapsed = current_frame - last_frame;

        if elapsed >= QUARANTINE_FRAMES as u64 {
            self.flush_all();
        } else {
            for f in (last_frame + 1)..=current_frame {
                let idx = (f as usize) % QUARANTINE_FRAMES;
                Self::drain_bucket(&mut self.buckets[idx]);
            }
        }
    }

    fn flush_all(&mut self) {
        for bucket in &mut self.buckets {
            Self::drain_bucket(bucket);
        }
    }

    #[inline]
    fn drain_bucket(bucket: &mut Vec<*mut c_void>) {
        if bucket.is_empty() {
            return;
        }
        for ptr in bucket.drain(..) {
            unsafe { libmimalloc::mi_free(ptr) };
        }
    }
}

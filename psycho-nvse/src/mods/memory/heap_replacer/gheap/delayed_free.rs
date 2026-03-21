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
//! All game object frees go through `GameHeap::Free` -> our `Gheap::free` ->
//! this quarantine. Verified by Ghidra audit: no bypass paths exist.
//!
//! # Safety model
//!
//! During normal gameplay (main loop running, `tick()` called every frame):
//! - No bucket limit -- ALL frees are quarantined, zero bypass
//! - Stale buckets flushed every frame (QUARANTINE_FRAMES zombie window)
//!
//! During loading screens (main loop not running, `tick()` not called):
//! - Frame counter is stale -- detected by push count without frame advance
//! - After `STALE_PUSH_LIMIT` pushes, bucket rotation bounds memory growth
//! - BSTaskManagerThread is ALWAYS active (Ghidra-verified: FUN_00c410b0
//!   never checks DAT_011dea2b) -- NEVER mi_free directly during loading
//!
//! # Performance
//!
//! - Zero contention: each thread has its own quarantine (thread-local)
//! - One `Vec::push` per free (amortized O(1)), no syscalls on hot path
//! - Proactive flush every frame via `tick()`

use libc::c_void;
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Number of frames to hold freed pointers before releasing to mimalloc.
///
/// Must be large enough for ALL subsystems to finish using stale references:
/// - IO thread: 1-2 frames (texture load tasks)
/// - AI threads: 1 frame (raycasting within single dispatch)
/// - SpeedTree: 1 frame (draw list consumed by render)
/// - NVSE plugins (Stewie's Tweaks, etc.): access deleted objects via
///   stale process/weapon refs for many frames after HAVOK_DEATH
/// - Game's own deferred systems: variable delay
///
/// The original SBM kept zombies FOREVER (until arena purge). We can't
/// do that, but 30 frames (500ms at 60fps) covers NVSE plugin access
/// patterns (dead creature weapon refs, process state changes, etc.).
/// Memory overhead: ~30 frames × ~1MB/frame = ~30MB zombie data.
/// At 800MB idle commit, well within the ~1.8GB VA ceiling.
///
/// The pressure relief system no longer flushes quarantine — the full
/// 30-frame window is always respected. This prevents a race where
/// BSTaskManagerThread picks up new QueuedTexture tasks referencing
/// quarantined memory between async flush return and mi_free.
///
/// Tuning: 3 frames was too short (Stewie's Tweaks crash on dead
/// creature weapon ref). 60 frames added unnecessary ~60MB overhead
/// that contributed to VA pressure during stress testing.
const QUARANTINE_FRAMES: usize = 30;

/// If this many pushes happen on a single thread without a frame advance,
/// perform an IO-locked flush: acquire the IO dequeue spin-lock (blocks
/// BSTaskManagerThread), flush all quarantine buckets, then release.
/// This prevents UAF (IO thread blocked) AND VA pressure (memory freed).
///
/// BSTaskManagerThread is ALWAYS active (Ghidra: FUN_00c410b0 never
/// checks DAT_011dea2b). The IO lock is required before any flush
/// during stale periods.
const STALE_PUSH_LIMIT: u32 = 50_000;

// ---------------------------------------------------------------------------
// Frame counter
// ---------------------------------------------------------------------------

/// Global frame counter, incremented once per frame by the main loop hook.
static FRAME_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Emergency flush flag. Set by Gheap::alloc OOM recovery when allocation
/// fails and this thread's quarantine is empty (the big data is on another
/// thread). Checked by push() on the main thread — when set, forces a
/// quarantine drain even during loading screens. At OOM, crash is worse
/// than stale reference risk.
static EMERGENCY_FLUSH: AtomicBool = AtomicBool::new(false);

/// Signal that an OOM occurred and quarantine needs emergency flushing.
pub fn signal_emergency_flush() {
    EMERGENCY_FLUSH.store(true, Ordering::Release);
}

// ---------------------------------------------------------------------------
// IO lock awareness
// ---------------------------------------------------------------------------

thread_local! {
    /// Set to true when the current thread already holds the IO dequeue lock
    /// (e.g., inside destruction_protocol). When set, io_locked_flush skips
    /// lock acquisition and flushes directly — the caller already guarantees
    /// BSTaskManagerThread can't dequeue.
    static IO_LOCK_HELD: Cell<bool> = const { Cell::new(false) };
}

/// RAII guard that sets IO_LOCK_HELD for the current scope.
/// Used by destruction_protocol to signal that quarantine flushes
/// during PDD can skip lock acquisition.
pub struct IoLockScope;

impl IoLockScope {
    pub fn enter() -> Self {
        IO_LOCK_HELD.with(|f| f.set(true));
        IoLockScope
    }
}

impl Drop for IoLockScope {
    fn drop(&mut self) {
        IO_LOCK_HELD.with(|f| f.set(false));
    }
}

// ---------------------------------------------------------------------------
// Public API (called from Gheap)
// ---------------------------------------------------------------------------

/// Advance the frame counter AND proactively flush stale buckets on the
/// calling thread (main thread). Must be called exactly once per frame.
#[inline]
pub fn tick() {
    FRAME_COUNTER.fetch_add(1, Ordering::Relaxed);

    if let Some(pr) = super::pressure::PressureRelief::instance() {
        // Calibrate baseline on first tick (main loop started, mods loaded).
        // Must be here, not DLL init — mods load 500MB+ between init and main menu.
        pr.calibrate_baseline();

        // Decrement the loading state counter if destruction_protocol left it
        // elevated. This runs at the start of the NEW frame, AFTER NVSE plugins
        // processed events on the previous frame with the counter > 0.
        pr.flush_pending_counter_decrement();
    }

    // Clear the texture dead set — after one frame, any new QueuedTexture
    // tasks will load fresh textures (not reference destroyed ones).
    crate::mods::memory::heap_replacer::hooks::clear_texture_dead_set();

    // Proactively flush stale buckets on the main thread.
    QUARANTINE.with(|q| {
        let q = unsafe { &mut *q.get() };
        let frame = FRAME_COUNTER.load(Ordering::Relaxed);
        if let Some(last) = q.last_frame
            && frame != last {
                if frame > last {
                    q.flush_stale(last, frame);
                }
                q.last_frame = Some(frame);
                q.stale_pushes = 0;
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
        // Emergency flush: another thread hit OOM and needs us to free memory.
        // Respect AI thread state — flushing while AI holds Havok entity
        // pointers causes broadphase crash. If AI active, defer to next push.
        if EMERGENCY_FLUSH.load(Ordering::Relaxed) {
            let ai_active = unsafe { *(0x011DFA19 as *const u8) != 0 };
            if !ai_active {
                EMERGENCY_FLUSH.store(false, Ordering::Release);
                self.flush_all();
            }
        }

        let frame = FRAME_COUNTER.load(Ordering::Relaxed);

        match self.last_frame {
            None => {
                self.last_frame = Some(frame);
                self.stale_pushes = 0;
            }
            Some(last) if frame != last => {
                // Only flush if real frame moved forward. If last > frame
                // (synthetic rotation during loading), just sync back.
                if frame > last {
                    self.flush_stale(last, frame);
                }
                self.last_frame = Some(frame);
                self.stale_pushes = 0;
            }
            _ => {}
        }

        // Bound quarantine growth during stale periods (loading screens,
        // CellTransitionHandler, PDD).
        //
        // Three strategies based on context:
        //
        // 1. IO_LOCK_HELD (PDD): flush directly, IO already locked.
        //    BSTaskManagerThread blocked, no UAF risk.
        //
        // 2. Loading screen (DAT_011dea2b != 0): do NOT drain at all.
        //    NVSE plugins (JIP LN) hold refs to forms destroyed during
        //    loading. After loading, CellChange events access those refs.
        //    ANY drain during loading risks recycling memory JIP needs.
        //    Let quarantine grow unbounded. Gheap::alloc OOM recovery
        //    (flush + mi_collect + retry) handles VA pressure as last resort.
        //
        // 3. Normal gameplay stale: io_locked_flush (blocks IO, flushes).
        self.stale_pushes += 1;
        if self.stale_pushes >= STALE_PUSH_LIMIT {
            let io_held = IO_LOCK_HELD.with(|f| f.get());
            if io_held {
                // Case 1: PDD — IO locked, safe to flush everything.
                self.stale_pushes = 0;
                for bucket in self.buckets.iter_mut() {
                    Self::drain_bucket(bucket);
                }
            } else {
                let loading = unsafe { *(0x011DEA2B as *const u8) != 0 };
                if loading {
                    // Case 2: Loading screen — bucket rotation.
                    // Drain the oldest slot (data from QUARANTINE_FRAMES
                    // rotations ago) but keep recent zombies for NVSE.
                    // Prevents unbounded VA consumption during loading
                    // while preserving zombie data for JIP CellChange events.
                    self.stale_pushes = 0;
                    let current = self.last_frame.unwrap_or(frame);
                    let next = current.wrapping_add(1);
                    let idx = (next as usize) % QUARANTINE_FRAMES;
                    Self::drain_bucket(&mut self.buckets[idx]);
                    self.last_frame = Some(next);
                } else {
                    // Case 3: Normal gameplay — check AI thread state.
                    // DAT_011dfa19: 1 = AI threads active, 0 = idle.
                    // AI threads hold Havok entity pointers from simulation
                    // islands. Flushing quarantine while AI is active recycles
                    // entity memory -> NULL in addEntitiesBatch -> crash.
                    // Only flush when BOTH IO and AI are safe.
                    let ai_active = unsafe { *(0x011DFA19 as *const u8) != 0 };
                    if ai_active {
                        // AI active — do NOT flush. Keep zombies.
                        // tick() will flush on next frame when AI is idle.
                    } else {
                        // AI idle + normal gameplay — IO-locked flush.
                        self.stale_pushes = 0;
                        unsafe { Self::io_locked_flush(&mut self.buckets) };
                    }
                }
            }
        }

        let slot = self.last_frame.unwrap_or(frame);
        let idx = (slot as usize) % QUARANTINE_FRAMES;
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

    /// Flush all quarantine buckets while holding the IO dequeue lock.
    /// BSTaskManagerThread is blocked from dequeuing new tasks during flush,
    /// preventing use-after-free on freed NiSourceTexture/NiPixelData.
    ///
    /// If IO_LOCK_HELD is set (caller already holds the lock, e.g.
    /// destruction_protocol), skips lock acquisition to avoid redundant
    /// spin-lock + semaphore probe overhead that causes FPS stutter.
    unsafe fn io_locked_flush(buckets: &mut [Vec<*mut c_void>; QUARANTINE_FRAMES]) {
        let already_held = IO_LOCK_HELD.with(|f| f.get());

        let needs_release = if already_held {
            false
        } else {
            use super::pressure::PressureRelief;
            unsafe { PressureRelief::io_lock_acquire() }
        };

        for bucket in buckets.iter_mut() {
            Self::drain_bucket(bucket);
        }

        if needs_release {
            use super::pressure::PressureRelief;
            unsafe { PressureRelief::io_lock_release() };
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

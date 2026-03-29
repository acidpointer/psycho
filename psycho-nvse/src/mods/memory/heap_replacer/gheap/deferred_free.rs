// Background GC for deferred mi_free.
//
// Main-thread frees push raw pointers into a thread-local Vec. At each
// frame boundary (Phase 7), the Vec is swapped out and handed to the GC
// thread as a "frame batch" tagged with the current frame number.
//
// The GC thread processes batches in FIFO order once they reach the
// minimum survival age (N frames). This guarantees freed memory stays
// readable for at least N frames -- matching SBM's pool behavior where
// freed blocks sit on the freelist indefinitely.
//
// Why a separate thread instead of Phase-7 drain:
//   - Zero main-thread cost (no mi_free burst, no write lock, no stutter)
//   - Runs on its own core, doesn't steal game frame time
//   - Decoupled from frame timing -- GC catches up during idle moments
//
// Why per-frame batches instead of per-pointer timestamps:
//   - Vec::push is ~5ns (no timestamp, no atomic)
//   - Frame boundary swap is one pointer swap per frame
//   - GC processes whole batches, not individual pointers (cache friendly)

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::collections::VecDeque;

use libc::c_void;

// Minimum frames a pointer must survive before mi_free.
// At 60fps this is ~83ms. BST texture tasks complete in 1-5ms.
// Conservative: covers even backed-up BST during stress.
const MIN_SURVIVAL_FRAMES: u64 = 5;

// GC poll interval. 1ms keeps latency low without burning CPU.
// The thread sleeps when no work is available.
const GC_POLL_MS: u32 = 1;

// -----------------------------------------------------------------------
// Frame counter (written by main thread at Phase 7, read by GC)
// -----------------------------------------------------------------------

static FRAME_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn current_frame() -> u64 {
    FRAME_COUNTER.load(Ordering::Relaxed)
}

// -----------------------------------------------------------------------
// Frame batch: one frame's worth of freed pointers
// -----------------------------------------------------------------------

struct FrameBatch {
    frame: u64,
    entries: Vec<*mut c_void>,
}

// Safety: pointers are only dereferenced (mi_free) on the GC thread.
// No aliasing -- once in the batch, no other thread touches them.
unsafe impl Send for FrameBatch {}

// -----------------------------------------------------------------------
// Inbox: main thread produces batches, GC thread consumes them
// -----------------------------------------------------------------------

// Mutex<VecDeque> is fine here. Contention is minimal:
//   - Main thread pushes once per frame (Phase 7)
//   - GC thread pops in bulk when batches are old enough
// A lock-free SPSC queue would save ~20ns/frame but adds complexity.
static INBOX: Mutex<VecDeque<FrameBatch>> = Mutex::new(VecDeque::new());

// -----------------------------------------------------------------------
// Per-thread pending buffer (main thread only, zero sync on push)
// -----------------------------------------------------------------------

thread_local! {
    static PENDING: std::cell::UnsafeCell<Vec<*mut c_void>> =
        const { std::cell::UnsafeCell::new(Vec::new()) };
}

// Push a freed pointer to the pending buffer.
// Called from the main-thread free path. Zero synchronization.
#[inline]
pub fn push(ptr: *mut c_void) {
    PENDING.with(|p| {
        let p = unsafe { &mut *p.get() };
        p.push(ptr);
    });
}

// Pending entry count for diagnostics. Approximate (races with push).
pub fn pending_count() -> usize {
    PENDING.with(|p| {
        let p = unsafe { &*p.get() };
        p.len()
    })
}

// -----------------------------------------------------------------------
// Frame tick: called once per frame at Phase 7 by the main thread
// -----------------------------------------------------------------------

// Swap out the pending buffer and hand it to the GC thread.
// Increments the frame counter. Cost: one Vec swap + one Mutex push.
pub fn frame_tick() {
    FRAME_COUNTER.fetch_add(1, Ordering::Relaxed);

    let batch = PENDING.with(|p| {
        let p = unsafe { &mut *p.get() };
        if p.is_empty() {
            return None;
        }
        Some(std::mem::take(p))
    });

    if let Some(entries) = batch {
        let frame = FRAME_COUNTER.load(Ordering::Relaxed);
        let count = entries.len();
        let mut inbox = INBOX.lock().unwrap_or_else(|e| e.into_inner());
        inbox.push_back(FrameBatch { frame, entries });
        drop(inbox);

        if count > 50_000 {
            log::debug!("[GC] Frame {} queued {} entries", frame, count);
        }
    }
}

// -----------------------------------------------------------------------
// Emergency flush: drain everything regardless of age.
// Called from OOM recovery when we must reclaim memory NOW.
// Runs on the CALLING thread (main or worker).
// -----------------------------------------------------------------------

pub unsafe fn emergency_flush() {
    // Drain the pending buffer directly (main thread only).
    PENDING.with(|p| {
        let p = unsafe { &mut *p.get() };
        for ptr in p.drain(..) {
            unsafe { libmimalloc::mi_free(ptr) };
        }
    });

    // Drain all batches from the inbox regardless of age.
    let mut inbox = INBOX.lock().unwrap_or_else(|e| e.into_inner());
    let batches: Vec<FrameBatch> = inbox.drain(..).collect();
    drop(inbox);

    let mut total = 0usize;
    for batch in batches {
        total += batch.entries.len();
        for ptr in batch.entries {
            unsafe { libmimalloc::mi_free(ptr) };
        }
    }

    if total > 0 {
        log::warn!("[GC] Emergency flush: {} entries", total);
    }

    unsafe { libmimalloc::mi_collect(true) };
}

// -----------------------------------------------------------------------
// GC thread
// -----------------------------------------------------------------------

pub fn start_gc_thread() {
    std::thread::Builder::new()
        .name("gheap-gc".into())
        .spawn(gc_loop)
        .ok();
}

fn gc_loop() {
    log::info!(
        "[GC] Started (survival={} frames, poll={}ms)",
        MIN_SURVIVAL_FRAMES, GC_POLL_MS,
    );

    loop {
        libpsycho::os::windows::winapi::sleep(GC_POLL_MS);

        let now = FRAME_COUNTER.load(Ordering::Relaxed);
        if now < MIN_SURVIVAL_FRAMES {
            continue; // not enough frames elapsed yet
        }
        let threshold = now - MIN_SURVIVAL_FRAMES;

        // Collect all batches that are old enough.
        let mut inbox = INBOX.lock().unwrap_or_else(|e| e.into_inner());
        let mut to_free: Vec<FrameBatch> = Vec::new();
        while let Some(front) = inbox.front() {
            if front.frame > threshold {
                break; // too young
            }
            to_free.push(inbox.pop_front().unwrap());
        }
        drop(inbox); // release lock before mi_free work

        if to_free.is_empty() {
            continue;
        }

        let mut total = 0usize;
        for batch in to_free {
            total += batch.entries.len();
            for ptr in batch.entries {
                unsafe { libmimalloc::mi_free(ptr) };
            }
        }

        if total > 10_000 {
            log::debug!("[GC] Freed {} entries (frame {})", total, now);
        }
    }
}

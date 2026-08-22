//! Memory pressure relief for the game heap.
//!
//! Pressure detection is handled by the watchdog thread (watchdog.rs).
//! This module provides:
//!   - baseline commit calibration;
//!   - an allocation-free watchdog-to-main-thread pressure mailbox; and
//!   - bounded empty-block relief at the existing Phase 10 boundary.
//!
//! # Hook positions
//!
//!   Phase 10 (hook_main_loop_maintenance): baseline calibration and pressure
//!   request consumption.

use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::block::TryRetireResult;

// ---------------------------------------------------------------------------
// PressureRelief
// ---------------------------------------------------------------------------

/// Tracks baseline commit.
///
/// Pressure detection is handled by the watchdog thread. This struct keeps the
/// baseline commit used for threshold computation.
pub struct PressureRelief {
    /// Commit at first tick. Used by watchdog for threshold computation.
    baseline_commit: AtomicUsize,
    request_generation: AtomicU64,
    handled_generation: AtomicU64,
    request_total_free: AtomicUsize,
    request_largest_free: AtomicUsize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PressureRequest {
    generation: u64,
    total_free: usize,
    largest_free: usize,
}

impl PressureRelief {
    fn new() -> Self {
        log::info!("[PRESSURE] Initialized");

        Self {
            baseline_commit: AtomicUsize::new(0),
            request_generation: AtomicU64::new(0),
            handled_generation: AtomicU64::new(0),
            request_total_free: AtomicUsize::new(0),
            request_largest_free: AtomicUsize::new(0),
        }
    }

    /// Get the calibrated baseline commit (0 if not yet calibrated).
    pub fn baseline_commit(&self) -> usize {
        self.baseline_commit.load(Ordering::Relaxed)
    }

    /// Measure baseline commit on first tick (main loop started, mods loaded).
    pub fn calibrate_baseline(&self) {
        if self.baseline_commit.load(Ordering::Relaxed) != 0 {
            return;
        }
        let commit = libmimalloc::process_info::MiMallocProcessInfo::get().get_current_commit();
        self.baseline_commit.store(commit, Ordering::Release);

        // Now that we know baseline, calculate VAS crisis thresholds
        // based on available VAS (from VirtualQuery at startup).
        super::allocator::calibrate_thresholds(commit);

        log::info!("[PRESSURE] Baseline calibrated: {}MB", commit / 1024 / 1024,);
    }

    /// Publish one watchdog sample that proves high process VAS pressure.
    ///
    /// The sampled values are stored before the release publication of the
    /// generation, so Phase 10 observes a coherent request after its acquire
    /// load. The watchdog is the only publisher.
    pub(crate) fn publish_vas_pressure(&self, total_free: usize, largest_free: usize) {
        self.request_total_free.store(total_free, Ordering::Relaxed);
        self.request_largest_free
            .store(largest_free, Ordering::Relaxed);
        self.request_generation.fetch_add(1, Ordering::Release);
    }

    /// Consume bounded allocator-owned relief at the Phase 10 main-thread
    /// boundary. A busy block allocator leaves the request pending rather than
    /// stalling the frame.
    pub(crate) fn relieve_pending_vas_pressure(&self) {
        let Some(request) = self.pending_request() else {
            return;
        };

        let TryRetireResult::Complete(result) = super::block::try_retire_empty_for_pressure()
        else {
            return;
        };
        self.handled_generation
            .store(request.generation, Ordering::Release);

        if result.slots_retired > 0 {
            log::warn!(
                "[PRESSURE] Released empty medium blocks: request={} retired={}/{} slots reserved={}MB committed={}MB failures={} sampled_free={}MB sampled_largest={}MB",
                request.generation,
                result.slots_retired,
                result.eligible_slots,
                result.reserved_bytes / super::vas::MB,
                result.committed_bytes / super::vas::MB,
                result.release_failures,
                request.total_free / super::vas::MB,
                request.largest_free / super::vas::MB,
            );
        } else {
            log::warn!(
                "[PRESSURE] No empty medium blocks released: request={} eligible={} failures={} sampled_free={}MB sampled_largest={}MB; live blocks retain their allocations",
                request.generation,
                result.eligible_slots,
                result.release_failures,
                request.total_free / super::vas::MB,
                request.largest_free / super::vas::MB,
            );
        }
    }

    fn pending_request(&self) -> Option<PressureRequest> {
        let generation = self.request_generation.load(Ordering::Acquire);
        if generation == 0 || generation == self.handled_generation.load(Ordering::Acquire) {
            return None;
        }
        Some(PressureRequest {
            generation,
            total_free: self.request_total_free.load(Ordering::Relaxed),
            largest_free: self.request_largest_free.load(Ordering::Relaxed),
        })
    }

    /// Get the global singleton (lazily initialized).
    pub fn instance() -> Option<&'static Self> {
        static INSTANCE: LazyLock<Option<PressureRelief>> =
            LazyLock::new(|| Some(PressureRelief::new()));
        INSTANCE.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailbox_keeps_the_latest_unhandled_vas_sample() {
        let pressure = PressureRelief::new();
        assert_eq!(pressure.pending_request(), None);

        pressure.publish_vas_pressure(180 * super::super::vas::MB, 80 * super::super::vas::MB);
        pressure.publish_vas_pressure(43 * super::super::vas::MB, super::super::vas::MB);

        let request = pressure.pending_request().expect("pending request");
        assert_eq!(request.generation, 2);
        assert_eq!(request.total_free, 43 * super::super::vas::MB);
        assert_eq!(request.largest_free, super::super::vas::MB);

        pressure
            .handled_generation
            .store(request.generation, Ordering::Release);
        assert_eq!(pressure.pending_request(), None);
    }
}

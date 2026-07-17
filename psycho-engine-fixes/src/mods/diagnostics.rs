//! Shared diagnostics helpers for hot-path instrumentation.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

static PERF_FREQUENCY: AtomicU64 = AtomicU64::new(0);
static HITCH_PROFILING: AtomicBool = AtomicBool::new(false);
static LOAD_DEPTH: AtomicU32 = AtomicU32::new(0);
static LOAD_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static LOAD_SITE: AtomicU32 = AtomicU32::new(0);
static LOAD_THREAD_ID: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy)]
#[repr(u32)]
pub(crate) enum LoadSite {
    TopLoadOriginalEnter = 1,
    ChangedFormOwnerEnter,
    LowProcessSanitizeEnter,
    LowProcessSanitizeExit,
    LowProcessPredecessorEnter,
    LowProcessPredecessorExit,
    ChangedFormOwnerExit,
    TopLoadOriginalExit,
    PostLoadPrepassEnter,
    PostLoadPrepassExit,
    TopLoadHookExit,
}

pub(crate) struct LoadSnapshot {
    pub sequence: u64,
    pub depth: u32,
    pub site: &'static str,
    pub thread_id: u32,
}

pub(crate) fn begin_load() {
    let thread_id = libpsycho::os::windows::winapi::get_current_thread_id();
    if LOAD_DEPTH.fetch_add(1, Ordering::AcqRel) == 0 {
        LOAD_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        LOAD_THREAD_ID.store(thread_id, Ordering::Release);
    }
    mark_load_site(LoadSite::TopLoadOriginalEnter);
}

pub(crate) fn finish_load() {
    mark_load_site(LoadSite::TopLoadHookExit);
    let depth = LOAD_DEPTH.load(Ordering::Acquire);
    if depth != 0 {
        LOAD_DEPTH.fetch_sub(1, Ordering::AcqRel);
    }
}

#[inline]
pub(crate) fn load_active() -> bool {
    LOAD_DEPTH.load(Ordering::Acquire) != 0
}

#[inline]
pub(crate) fn mark_load_site(site: LoadSite) {
    if !load_active() {
        return;
    }
    let thread_id = libpsycho::os::windows::winapi::get_current_thread_id();
    if LOAD_THREAD_ID.load(Ordering::Acquire) != thread_id {
        return;
    }
    LOAD_SITE.store(site as u32, Ordering::Release);
}

pub(crate) fn load_snapshot() -> LoadSnapshot {
    LoadSnapshot {
        sequence: LOAD_SEQUENCE.load(Ordering::Relaxed),
        depth: LOAD_DEPTH.load(Ordering::Acquire),
        site: load_site_name(LOAD_SITE.load(Ordering::Acquire)),
        thread_id: LOAD_THREAD_ID.load(Ordering::Acquire),
    }
}

fn load_site_name(site: u32) -> &'static str {
    match site {
        x if x == LoadSite::TopLoadOriginalEnter as u32 => "top-load-original-enter",
        x if x == LoadSite::ChangedFormOwnerEnter as u32 => "changed-form-owner-enter",
        x if x == LoadSite::LowProcessSanitizeEnter as u32 => "lowprocess-sanitize-enter",
        x if x == LoadSite::LowProcessSanitizeExit as u32 => "lowprocess-sanitize-exit",
        x if x == LoadSite::LowProcessPredecessorEnter as u32 => "lowprocess-predecessor-enter",
        x if x == LoadSite::LowProcessPredecessorExit as u32 => "lowprocess-predecessor-exit",
        x if x == LoadSite::ChangedFormOwnerExit as u32 => "changed-form-owner-exit",
        x if x == LoadSite::TopLoadOriginalExit as u32 => "top-load-original-exit",
        x if x == LoadSite::PostLoadPrepassEnter as u32 => "post-load-prepass-enter",
        x if x == LoadSite::PostLoadPrepassExit as u32 => "post-load-prepass-exit",
        x if x == LoadSite::TopLoadHookExit as u32 => "top-load-hook-exit",
        _ => "none",
    }
}

/// Configures opt-in QPC timing for frame hitch investigations.
pub(crate) fn configure_hitch_profiling(enabled: bool) {
    HITCH_PROFILING.store(enabled, Ordering::Release);
}

/// Returns true when focused hitch profiling may perform QPC reads.
#[inline]
pub(crate) fn hitch_profiling_enabled() -> bool {
    HITCH_PROFILING.load(Ordering::Acquire)
}

/// Lightweight QPC stopwatch used by optional diagnostics.
///
/// A zero `start_ticks` value means timing is disabled or unavailable. This
/// lets hot paths pass a stopwatch around without branching at every call site.
#[derive(Clone, Copy)]
pub(crate) struct Stopwatch {
    start_ticks: u64,
}

impl Stopwatch {
    /// Starts a stopwatch immediately.
    ///
    /// Use this only after the caller has already decided that timing is needed.
    #[inline]
    pub(crate) fn start() -> Self {
        Self {
            start_ticks: perf_counter(),
        }
    }

    /// Starts a stopwatch only when hitch profiling is enabled.
    ///
    /// This is the default for frame and guard telemetry; when profiling is
    /// disabled, it avoids QPC calls in game hot paths.
    #[inline]
    pub(crate) fn start_if_hitch_profiling() -> Self {
        if hitch_profiling_enabled() {
            Self::start()
        } else {
            Self { start_ticks: 0 }
        }
    }

    /// Returns elapsed microseconds, or `None` if timing was disabled or invalid.
    #[inline]
    pub(crate) fn elapsed_us(self) -> Option<u64> {
        if self.start_ticks == 0 {
            return None;
        }

        let end_ticks = perf_counter();
        if end_ticks <= self.start_ticks {
            return None;
        }

        let elapsed = ticks_to_us(end_ticks - self.start_ticks);
        (elapsed != 0).then_some(elapsed)
    }
}

/// Reads the high-resolution performance counter.
///
/// Returns zero if QPC is unavailable so callers can cheaply skip the sample.
#[inline]
pub(crate) fn perf_counter() -> u64 {
    libpsycho::os::windows::winapi::query_performance_counter()
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(0)
}

/// Converts QPC ticks to microseconds using a cached frequency.
#[inline]
pub(crate) fn ticks_to_us(ticks: u64) -> u64 {
    let freq = perf_frequency();
    if freq == 0 {
        return 0;
    }

    ticks.saturating_mul(1_000_000) / freq
}

/// Atomically raises a maximum value without taking a lock.
pub(crate) fn update_max_u64(slot: &AtomicU64, value: u64) {
    let mut old = slot.load(Ordering::Relaxed);
    while value > old {
        match slot.compare_exchange_weak(old, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(next) => old = next,
        }
    }
}

/// Throttles repetitive logs to counts 1, 2, 4, 8, ...
#[inline]
pub(crate) fn should_log_power_of_two(value: u64) -> bool {
    value == 1 || value.is_power_of_two()
}

/// Returns true at most once per interval across competing threads.
///
/// The first call only initializes the timestamp and returns false. This avoids
/// logging an immediate zero-length window at startup.
pub(crate) fn should_tick(last_tick: &AtomicU32, interval_ms: u32) -> bool {
    let now = libpsycho::os::windows::winapi::get_tick_count();
    let last = last_tick.load(Ordering::Acquire);
    if last == 0 {
        let _ = last_tick.compare_exchange(0, now, Ordering::AcqRel, Ordering::Relaxed);
        return false;
    }
    if now.wrapping_sub(last) < interval_ms {
        return false;
    }

    last_tick
        .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
        .is_ok()
}

/// Returns cached QPC frequency, or zero if the counter is unavailable.
fn perf_frequency() -> u64 {
    let current = PERF_FREQUENCY.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }

    let freq = libpsycho::os::windows::winapi::query_performance_frequency()
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(0);
    if freq != 0 {
        PERF_FREQUENCY.store(freq, Ordering::Release);
    }
    freq
}

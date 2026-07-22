//! Background memory telemetry thread.
//!
//! Polls process memory periodically, tracks growth rate via integer EMA,
//! and emits diagnostic logs.
//!
//! The watchdog does NOT call havok_gc or mi_collect. An earlier design
//! ran them on this thread under the assumption that havok_gc only
//! touched hkMemorySystem and not the physics world; a crash in AI
//! Linear Task Thread state ruled that out. FUN_00c459d0 takes the
//! Havok critical section and then calls into entity / broadphase
//! helpers that the main thread is mutating concurrently -- so off
//! the main thread it races with the physics step and frees objects
//! the stepper is walking.
//!
//! Cleanup (havok_gc / mi_collect) only runs on the main thread at
//! Phase 7/8 hooks, where it is serialised against physics and AI.
//! Per-tier allocators do not decommit, so no background reclaim
//! path is needed here.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};

use libmimalloc::process_info::MiMallocProcessInfo;

use super::engine::globals;
use super::pressure::PressureRelief;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Poll interval in milliseconds.
///
/// `mi_process_info` reaches Windows process accounting APIs
/// (`GetProcessTimes` / `GetProcessMemoryInfo`). Polling it at 250ms
/// caused visible 1-3ms frame hitches on high-FPS playthroughs. Keep
/// this watchdog on a diagnostics cadence instead of a frame-pacing
/// cadence.
const POLL_MS: u32 = 5_000;

/// Detailed allocator/VAS diagnostics interval (every N polls).
///
/// The five-second poll keeps growth tracking and failed-reservation retry
/// state responsive. Full process-map walks, allocator snapshots, sorting, and
/// log writes are support telemetry and stay off the frame-pacing cadence.
const DETAIL_INTERVAL: u32 = 12;

/// Human-facing summary interval. One summary accompanies each detailed poll.
const INFO_SUMMARY_INTERVAL: u32 = DETAIL_INTERVAL;

/// Growth thresholds as fraction of headroom (available_vas - baseline).
/// Proportional thresholds adapt to any modpack size:
///   Light (headroom=2596MB): normal=779, aggressive=1298, critical=1817
///   Heavy (headroom=1960MB): normal=588, aggressive=980, critical=1372
///
/// Fallback absolute values used when headroom is not yet calibrated.
const NORMAL_GROWTH_PCT: f64 = 0.30;
const AGGRESSIVE_GROWTH_PCT: f64 = 0.50;
const CRITICAL_GROWTH_PCT: f64 = 0.70;

/// Absolute fallback thresholds before headroom is calibrated.
const NORMAL_GROWTH_FALLBACK: usize = 500 * 1024 * 1024;
const CRITICAL_GROWTH_FALLBACK: usize = 1200 * 1024 * 1024;

/// During loading, lower all thresholds by this amount.
const LOADING_THRESHOLD_REDUCTION: usize = 200 * 1024 * 1024; // 200MB

/// Fallback absolute threshold (bytes) used when baseline is not yet
/// calibrated. Prevents a blind spot during early gameplay before
/// Phase 10 runs calibration. Normal gameplay commit is ~800MB-1.2GB;
/// 2GB is high enough to avoid false positives during startup but low
/// enough to catch pathological early spikes.
const FALLBACK_ABSOLUTE_THRESHOLD: usize = 2 * 1024 * 1024 * 1024; // 2GB

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
enum PressureState {
    Normal = 0,
    Watch = 1,
    High = 2,
}

// ---------------------------------------------------------------------------
// Shared atomic state (read by main thread, written by watchdog)
// ---------------------------------------------------------------------------

/// Smoothed commit growth rate in bytes/second (can be negative).
static GROWTH_RATE: AtomicI32 = AtomicI32::new(0);

/// Last commit sample for rate computation.
static LAST_COMMIT: AtomicUsize = AtomicUsize::new(0);
static COMMIT_STATE: AtomicUsize = AtomicUsize::new(PressureState::Normal as usize);
static FREE_VAS_STATE: AtomicUsize = AtomicUsize::new(PressureState::Normal as usize);
static HOLE_STATE: AtomicUsize = AtomicUsize::new(PressureState::Normal as usize);
static LAST_POOL_EXHAUST: AtomicU64 = AtomicU64::new(0);
static LAST_BLOCK_OVERFLOW: AtomicU64 = AtomicU64::new(0);
static LAST_BLOCK_FAILURE: AtomicU64 = AtomicU64::new(0);
static LAST_VA_FAILURE: AtomicU64 = AtomicU64::new(0);

static PROCESS_SAMPLE_GENERATION: AtomicU32 = AtomicU32::new(0);
static PROCESS_SAMPLE_TIME_MS: AtomicU64 = AtomicU64::new(0);
static PROCESS_RSS: AtomicU64 = AtomicU64::new(0);
static PROCESS_PEAK_RSS: AtomicU64 = AtomicU64::new(0);
static PROCESS_COMMIT: AtomicU64 = AtomicU64::new(0);
static PROCESS_PEAK_COMMIT: AtomicU64 = AtomicU64::new(0);
static PROCESS_PAGE_FAULTS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Default)]
pub(crate) struct ProcessSnapshot {
    pub sample_time_ms: u64,
    pub rss: u64,
    pub peak_rss: u64,
    pub commit: u64,
    pub peak_commit: u64,
    pub page_faults: u64,
}

pub(crate) fn process_snapshot() -> Option<ProcessSnapshot> {
    for _ in 0..3 {
        let before = PROCESS_SAMPLE_GENERATION.load(Ordering::Acquire);
        if before == 0 || before & 1 != 0 {
            continue;
        }
        let snapshot = ProcessSnapshot {
            sample_time_ms: PROCESS_SAMPLE_TIME_MS.load(Ordering::Relaxed),
            rss: PROCESS_RSS.load(Ordering::Relaxed),
            peak_rss: PROCESS_PEAK_RSS.load(Ordering::Relaxed),
            commit: PROCESS_COMMIT.load(Ordering::Relaxed),
            peak_commit: PROCESS_PEAK_COMMIT.load(Ordering::Relaxed),
            page_faults: PROCESS_PAGE_FAULTS.load(Ordering::Relaxed),
        };
        if PROCESS_SAMPLE_GENERATION.load(Ordering::Acquire) == before {
            return Some(snapshot);
        }
    }
    None
}

pub(crate) fn publish_process_snapshot(info: &MiMallocProcessInfo) {
    PROCESS_SAMPLE_GENERATION.fetch_add(1, Ordering::AcqRel);
    PROCESS_SAMPLE_TIME_MS.store(
        u64::from(libpsycho::os::windows::winapi::get_tick_count()),
        Ordering::Relaxed,
    );
    PROCESS_RSS.store(info.get_current_rss() as u64, Ordering::Relaxed);
    PROCESS_PEAK_RSS.store(info.get_peak_rss() as u64, Ordering::Relaxed);
    PROCESS_COMMIT.store(info.get_current_commit() as u64, Ordering::Relaxed);
    PROCESS_PEAK_COMMIT.store(info.get_peak_commit() as u64, Ordering::Relaxed);
    PROCESS_PAGE_FAULTS.store(info.get_page_faults() as u64, Ordering::Relaxed);
    PROCESS_SAMPLE_GENERATION.fetch_add(1, Ordering::Release);
}

// ---------------------------------------------------------------------------
// Public API (called from main thread)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Watchdog thread
// ---------------------------------------------------------------------------

/// Background memory watchdog.
///
/// Spawns a thread that polls mimalloc commit, tracks growth rate,
/// and sets atomic flags for the main thread to consume at Phase 7.
/// Also performs periodic diagnostic logging (RSS, commit, faults).
pub struct Watchdog {
    run: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Watchdog {
    /// Spawn the watchdog thread. Returns a handle that stops the
    /// thread on drop.
    pub fn start() -> Self {
        let run = Arc::new(AtomicBool::new(true));
        let run_clone = run.clone();

        let handle = match thread::Builder::new()
            .name("gheap-watchdog".into())
            .spawn(move || watchdog_loop(run_clone))
        {
            Ok(handle) => Some(handle),
            Err(err) => {
                run.store(false, Ordering::Release);
                log::error!("[MEM] Failed to spawn watchdog thread: {err}");
                None
            }
        };

        if handle.is_some() {
            log::info!("[MEM] Watchdog started");
        }
        log::debug!(
            "[MEM] Watchdog config: poll={}ms detail={}ms, growth thresholds={}%/{}%/{}% of headroom",
            POLL_MS,
            POLL_MS * DETAIL_INTERVAL,
            (NORMAL_GROWTH_PCT * 100.0) as u32,
            (AGGRESSIVE_GROWTH_PCT * 100.0) as u32,
            (CRITICAL_GROWTH_PCT * 100.0) as u32,
        );

        Self { run, handle }
    }

    /// Return whether the watchdog thread was created successfully.
    pub fn is_running(&self) -> bool {
        self.handle.is_some()
    }
}

fn log_allocator_events() {
    let pool_exhaust = super::pool::exhaust_count();
    let block_overflow = super::allocator::block_overflow_count();
    let block_fail = super::block::fail_count();
    let va_fail = super::va_alloc::fail_count();
    let new_pool_exhaust =
        pool_exhaust.saturating_sub(LAST_POOL_EXHAUST.swap(pool_exhaust, Ordering::AcqRel));
    let new_block_overflow =
        block_overflow.saturating_sub(LAST_BLOCK_OVERFLOW.swap(block_overflow, Ordering::AcqRel));
    let new_block_fail =
        block_fail.saturating_sub(LAST_BLOCK_FAILURE.swap(block_fail, Ordering::AcqRel));
    let new_va_fail = va_fail.saturating_sub(LAST_VA_FAILURE.swap(va_fail, Ordering::AcqRel));

    if new_pool_exhaust == 0 && new_block_overflow == 0 && new_block_fail == 0 && new_va_fail == 0 {
        return;
    }

    log::warn!(
        "[MEM] allocator fallback events: pool_exhaust+{} total={} block_overflow+{} total={} block_fail+{} total={} va_fail+{} total={}",
        new_pool_exhaust,
        pool_exhaust,
        new_block_overflow,
        block_overflow,
        new_block_fail,
        block_fail,
        new_va_fail,
        va_fail,
    );
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.run.store(false, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn watchdog_loop(run: Arc<AtomicBool>) {
    let mut poll_count: u32 = 0;
    let mut prev_rate: i32 = 0;

    loop {
        if !run.load(Ordering::Acquire) {
            return;
        }

        libpsycho::os::windows::winapi::sleep(POLL_MS);
        super::hitch::measure_span(super::hitch::Span::MemoryWatchdog, || {
            poll_count = poll_count.wrapping_add(1);
            super::pool::allow_reservation_retries();

            let info = MiMallocProcessInfo::get();
            publish_process_snapshot(&info);
            let commit = info.get_current_commit();

            // --- Rate tracking ---
            let prev_commit = LAST_COMMIT.swap(commit, Ordering::Relaxed);
            let first_sample = prev_commit == 0;
            let rate_sample = if !first_sample {
                let delta = commit as i64 - prev_commit as i64;
                (delta * 1000 / POLL_MS as i64) as i32
            } else {
                0
            };

            // Integer EMA: rate = (3 * sample + 7 * prev) / 10
            let smoothed = (3i64 * rate_sample as i64 + 7i64 * prev_rate as i64) / 10;
            prev_rate = smoothed as i32;
            GROWTH_RATE.store(prev_rate, Ordering::Relaxed);

            // --- Diagnostic logging ---
            log_diagnostics(poll_count, &info);
        });
    }
}

fn log_diagnostics(poll_count: u32, info: &MiMallocProcessInfo) {
    if !poll_count.is_multiple_of(DETAIL_INTERVAL) {
        return;
    }

    super::hang::log_if_main_stale();

    let vas = super::vas::sample();
    log_pressure(
        info.get_current_commit(),
        vas.map(|summary| summary.total_free),
    );

    log::debug!(
        "[MEM] RSS: {} | Peak: {} | Commit: {} | PeakCommit: {} | Faults: {:.1}/s | CPU eff: {:.0}%",
        info.memory_usage_human(),
        info.peak_memory_usage_human(),
        info.virtual_memory_usage_human(),
        libpsycho::common::helpers::format_bytes(info.get_peak_commit()),
        info.page_fault_rate_per_second(),
        info.cpu_efficiency_percent(),
    );

    let rate = GROWTH_RATE.load(Ordering::Relaxed);
    let pool_reserved_mb = super::pool::reserved_bytes() / 1024 / 1024;
    let pool_mb = super::pool::committed_bytes() / 1024 / 1024;
    let pool_metadata_mb = super::pool::metadata_bytes() / 1024 / 1024;
    let pool_metadata_reserved_mb = super::pool::metadata_reserved_bytes() / 1024 / 1024;
    let pool_live = super::pool::live_cells();
    let pool_overflow_user_mb = super::pool::overflow_user_reserved_bytes() / 1024 / 1024;
    let pool_overflow_metadata_mb = super::pool::overflow_metadata_reserved_bytes() / 1024 / 1024;
    let blocks = super::block::try_snapshot();
    let block_sample = if blocks.is_some() { "fresh" } else { "miss" };
    let blocks = blocks.unwrap_or_default();
    let va_live = super::va_alloc::live_bytes() / 1024 / 1024;
    let va_peak = super::va_alloc::peak_live_bytes() / 1024 / 1024;
    let va_max = super::va_alloc::max_allocation_bytes() / 1024 / 1024;
    log::debug!(
        "[MEM] Pool: {}MB cells + {}/{}MB metadata / {}MB user reserved (overflow={}/{}MB user/meta, {} live) | Blocks: {} slots, {}/{}MB live/committed, {} allocs, sample={} | VA: {}/{}MB live/peak, {}MB max | Rate: {}/s",
        pool_mb,
        pool_metadata_mb,
        pool_metadata_reserved_mb,
        pool_reserved_mb,
        pool_overflow_user_mb,
        pool_overflow_metadata_mb,
        pool_live,
        blocks.slots,
        blocks.live_bytes / 1024 / 1024,
        blocks.committed_bytes / 1024 / 1024,
        blocks.live_allocations,
        block_sample,
        va_live,
        va_peak,
        va_max,
        format_rate(rate),
    );
    let mut class_usage = super::pool::class_usage();
    class_usage.sort_unstable_by_key(|usage| std::cmp::Reverse(usage.live_cells));
    log::debug!(
        "[MEM] Pool top live: #{} {}B={} ({}/{}MB), #{} {}B={} ({}/{}MB), #{} {}B={} ({}/{}MB), #{} {}B={} ({}/{}MB)",
        class_usage[0].class_index,
        class_usage[0].item_size,
        class_usage[0].live_cells,
        class_usage[0].committed_bytes / 1024 / 1024,
        class_usage[0].reserved_bytes / 1024 / 1024,
        class_usage[1].class_index,
        class_usage[1].item_size,
        class_usage[1].live_cells,
        class_usage[1].committed_bytes / 1024 / 1024,
        class_usage[1].reserved_bytes / 1024 / 1024,
        class_usage[2].class_index,
        class_usage[2].item_size,
        class_usage[2].live_cells,
        class_usage[2].committed_bytes / 1024 / 1024,
        class_usage[2].reserved_bytes / 1024 / 1024,
        class_usage[3].class_index,
        class_usage[3].item_size,
        class_usage[3].live_cells,
        class_usage[3].committed_bytes / 1024 / 1024,
        class_usage[3].reserved_bytes / 1024 / 1024,
    );
    log_allocator_events();

    if let Some(vas) = vas {
        log::debug!(
            "[VAS watchdog] free={}MB largest=0x{:08x}+{}MB second=0x{:08x}+{}MB reserve={}MB commit={}MB regions={} holes={}",
            vas.total_free / super::vas::MB,
            vas.largest_base,
            vas.largest_free / super::vas::MB,
            vas.second_base,
            vas.second_free / super::vas::MB,
            vas.total_reserve / super::vas::MB,
            vas.total_commit / super::vas::MB,
            vas.regions,
            vas.holes,
        );
        log_largest_hole_pressure(vas);

        if poll_count.is_multiple_of(INFO_SUMMARY_INTERVAL) {
            log::info!(
                "[MEM] commit={} peak={} pool={}/{}MB blocks={} va={}MB largest_free={}MB total_free={}MB rate={}/s",
                info.virtual_memory_usage_human(),
                libpsycho::common::helpers::format_bytes(info.get_peak_commit()),
                pool_mb,
                pool_reserved_mb,
                blocks.slots,
                va_live,
                vas.largest_free / super::vas::MB,
                vas.total_free / super::vas::MB,
                format_rate(rate),
            );
        }
    }
}

fn log_pressure(commit: usize, free_vas: Option<usize>) {
    let Some(pr) = PressureRelief::instance() else {
        return;
    };

    let baseline = pr.baseline_commit();
    let loading = globals::is_loading();
    let headroom = super::allocator::get_headroom();

    let (growth, normal_thresh, high_thresh) = if baseline > 0 && headroom > 0 {
        let reduction = if loading {
            LOADING_THRESHOLD_REDUCTION
        } else {
            0
        };
        let g = commit.saturating_sub(baseline);
        let normal = ((headroom as f64 * NORMAL_GROWTH_PCT) as usize).saturating_sub(reduction);
        let high = ((headroom as f64 * CRITICAL_GROWTH_PCT) as usize).saturating_sub(reduction);
        (g, normal, high)
    } else if baseline > 0 {
        let reduction = if loading {
            LOADING_THRESHOLD_REDUCTION
        } else {
            0
        };
        (
            commit.saturating_sub(baseline),
            NORMAL_GROWTH_FALLBACK.saturating_sub(reduction),
            CRITICAL_GROWTH_FALLBACK.saturating_sub(reduction),
        )
    } else {
        let reduction = if loading {
            LOADING_THRESHOLD_REDUCTION
        } else {
            0
        };
        let normal_abs = FALLBACK_ABSOLUTE_THRESHOLD.saturating_sub(reduction);
        (commit, normal_abs, normal_abs + 500 * 1024 * 1024)
    };

    if let Some(free_vas) = free_vas {
        let free_state = classify_free_vas(free_vas);
        log_state_change(
            &FREE_VAS_STATE,
            free_state,
            || {
                log::info!(
                    "[MEM] Free VAS recovered: free={}MB",
                    free_vas / 1024 / 1024,
                )
            },
            || log::info!("[MEM] Free VAS watch: free={}MB", free_vas / 1024 / 1024,),
            || {
                log::warn!(
                    "[MEM] Free VAS low: free={}MB. Heavy texture or cell streaming allocations may fail.",
                    free_vas / 1024 / 1024,
                )
            },
        );
    }

    let commit_state = classify_commit_growth(growth, normal_thresh, high_thresh);
    let rate = GROWTH_RATE.load(Ordering::Relaxed);
    log_state_change(
        &COMMIT_STATE,
        commit_state,
        || {
            log::info!(
                "[MEM] Commit pressure recovered: commit={}MB growth={}MB",
                commit / 1024 / 1024,
                growth / 1024 / 1024,
            )
        },
        || {
            log::info!(
                "[MEM] Commit pressure watch: commit={}MB growth={}MB rate={}/s",
                commit / 1024 / 1024,
                growth / 1024 / 1024,
                format_rate(rate),
            )
        },
        || {
            log::warn!(
                "[MEM] Commit pressure high: commit={}MB growth={}MB rate={}/s",
                commit / 1024 / 1024,
                growth / 1024 / 1024,
                format_rate(rate),
            )
        },
    );
}

fn log_largest_hole_pressure(vas: super::vas::Summary) {
    let old = state_from_usize(HOLE_STATE.load(Ordering::Acquire));
    let state = classify_largest_hole(vas.largest_free, old);
    log_state_change(
        &HOLE_STATE,
        state,
        || {
            log::info!(
                "[MEM] VAS fragmentation recovered: largest_free={}MB total_free={}MB",
                vas.largest_free / super::vas::MB,
                vas.total_free / super::vas::MB,
            )
        },
        || {
            log::info!(
                "[MEM] VAS fragmentation watch: largest_free={}MB total_free={}MB",
                vas.largest_free / super::vas::MB,
                vas.total_free / super::vas::MB,
            )
        },
        || {
            log::warn!(
                "[MEM] VAS fragmentation high: largest_free={}MB total_free={}MB. Large texture or D3D allocations may fail.",
                vas.largest_free / super::vas::MB,
                vas.total_free / super::vas::MB,
            )
        },
    );
}

fn classify_free_vas(free_vas: usize) -> PressureState {
    if free_vas <= super::allocator::VAS_EMERGENCY_REMAINING {
        PressureState::High
    } else if free_vas <= super::allocator::VAS_CRITICAL_REMAINING {
        PressureState::Watch
    } else {
        PressureState::Normal
    }
}

fn classify_commit_growth(growth: usize, normal: usize, high: usize) -> PressureState {
    if growth >= high {
        PressureState::High
    } else if growth >= normal && GROWTH_RATE.load(Ordering::Relaxed) > 0 {
        PressureState::Watch
    } else {
        PressureState::Normal
    }
}

fn classify_largest_hole(largest: usize, old: PressureState) -> PressureState {
    if largest <= 96 * super::vas::MB {
        PressureState::High
    } else if largest <= super::vas::CRITICAL_LARGEST_HOLE
        || (old != PressureState::Normal && largest <= 160 * super::vas::MB)
    {
        PressureState::Watch
    } else {
        PressureState::Normal
    }
}

fn log_state_change(
    state: &AtomicUsize,
    new: PressureState,
    normal: impl FnOnce(),
    watch: impl FnOnce(),
    high: impl FnOnce(),
) {
    let old = state.swap(new as usize, Ordering::AcqRel);
    if old == new as usize {
        return;
    }

    match new {
        PressureState::Normal => normal(),
        PressureState::Watch => watch(),
        PressureState::High => high(),
    }
}

fn state_from_usize(value: usize) -> PressureState {
    match value {
        1 => PressureState::Watch,
        2 => PressureState::High,
        _ => PressureState::Normal,
    }
}

fn format_rate(bytes_per_sec: i32) -> String {
    let abs = bytes_per_sec.unsigned_abs();
    let sign = if bytes_per_sec < 0 { "-" } else { "+" };
    if abs >= 1024 * 1024 {
        format!("{}{}MB", sign, abs / 1024 / 1024)
    } else if abs >= 1024 {
        format!("{}{}KB", sign, abs / 1024)
    } else {
        format!("{}{}B", sign, abs)
    }
}

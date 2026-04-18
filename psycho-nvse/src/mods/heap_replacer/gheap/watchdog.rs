//! Background memory telemetry thread.
//!
//! Polls mimalloc commit every 250ms, tracks growth rate via integer EMA,
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

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use libmimalloc::process_info::MiMallocProcessInfo;

use super::super::mem_stats;
use super::engine::globals;
use super::pressure::PressureRelief;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Poll interval in milliseconds. 250ms gives 2x faster detection
/// with no game impact (background thread, only sets atomic flags).
const POLL_MS: u32 = 250;

/// Diagnostic logging interval (every N polls = every N*POLL_MS ms).
/// 20 polls * 250ms = 5 seconds, matching the old monitor interval.
const LOG_INTERVAL: u32 = 20;

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
const AGGRESSIVE_GROWTH_FALLBACK: usize = 800 * 1024 * 1024;
const CRITICAL_GROWTH_FALLBACK: usize = 1200 * 1024 * 1024;

/// During loading, lower all thresholds by this amount.
const LOADING_THRESHOLD_REDUCTION: usize = 200 * 1024 * 1024; // 200MB

/// Fallback absolute threshold (bytes) used when baseline is not yet
/// calibrated. Prevents a blind spot during early gameplay before
/// Phase 10 runs calibration. Normal gameplay commit is ~800MB-1.2GB;
/// 2GB is high enough to avoid false positives during startup but low
/// enough to catch pathological early spikes.
const FALLBACK_ABSOLUTE_THRESHOLD: usize = 2 * 1024 * 1024 * 1024; // 2GB

// ---------------------------------------------------------------------------
// Shared atomic state (read by main thread, written by watchdog)
// ---------------------------------------------------------------------------

/// Smoothed commit growth rate in bytes/second (can be negative).
static GROWTH_RATE: AtomicI32 = AtomicI32::new(0);

/// Last commit sample for rate computation.
static LAST_COMMIT: AtomicUsize = AtomicUsize::new(0);

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

        let handle = thread::Builder::new()
            .name("gheap-watchdog".into())
            .spawn(move || watchdog_loop(run_clone))
            .expect("failed to spawn watchdog thread");

        log::info!(
            "[WATCHDOG] Started (poll={}ms, growth thresholds={}%/{}%/{}% of headroom)",
            POLL_MS,
            (NORMAL_GROWTH_PCT * 100.0) as u32,
            (AGGRESSIVE_GROWTH_PCT * 100.0) as u32,
            (CRITICAL_GROWTH_PCT * 100.0) as u32,
        );

        Self {
            run,
            handle: Some(handle),
        }
    }
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
        poll_count = poll_count.wrapping_add(1);

        let info = MiMallocProcessInfo::get();
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

        // --- Pressure telemetry (log-only, no cleanup) ---
        // The watchdog must not call game code. It samples commit +
        // free VAS and logs when growth crosses thresholds; any real
        // reclamation happens on the main thread at Phase 7/8.
        if let Some(pr) = PressureRelief::instance() {
            let baseline = pr.baseline_commit();
            let loading = globals::is_loading();
            let headroom = super::allocator::get_headroom();
            let free_vas = super::allocator::current_free_vas();

            let (growth, normal_thresh, critical_thresh) = if baseline > 0 && headroom > 0 {
                let reduction = if loading { LOADING_THRESHOLD_REDUCTION } else { 0 };
                let g = commit.saturating_sub(baseline);
                let normal = ((headroom as f64 * NORMAL_GROWTH_PCT) as usize)
                    .saturating_sub(reduction);
                let critical = ((headroom as f64 * CRITICAL_GROWTH_PCT) as usize)
                    .saturating_sub(reduction);
                (g, normal, critical)
            } else if baseline > 0 {
                let reduction = if loading { LOADING_THRESHOLD_REDUCTION } else { 0 };
                (
                    commit.saturating_sub(baseline),
                    NORMAL_GROWTH_FALLBACK.saturating_sub(reduction),
                    CRITICAL_GROWTH_FALLBACK.saturating_sub(reduction),
                )
            } else {
                let reduction = if loading { LOADING_THRESHOLD_REDUCTION } else { 0 };
                let normal_abs = FALLBACK_ABSOLUTE_THRESHOLD.saturating_sub(reduction);
                (commit, normal_abs, normal_abs + 500 * 1024 * 1024)
            };

            if free_vas <= super::allocator::VAS_CRITICAL_REMAINING {
                log::warn!(
                    "[WATCHDOG] VAS CRITICAL: free={}MB (threshold={}MB)",
                    free_vas / 1024 / 1024,
                    super::allocator::VAS_CRITICAL_REMAINING / 1024 / 1024,
                );
            } else if growth >= critical_thresh {
                log::warn!(
                    "[WATCHDOG] Commit pressure CRITICAL: commit={}MB growth={}MB rate={}/s",
                    commit / 1024 / 1024,
                    growth / 1024 / 1024,
                    format_rate(prev_rate),
                );
            } else if growth >= normal_thresh && prev_rate > 0 {
                log::info!(
                    "[WATCHDOG] Commit pressure: commit={}MB growth={}MB rate={}/s",
                    commit / 1024 / 1024,
                    growth / 1024 / 1024,
                    format_rate(prev_rate),
                );
            }
        }

        // --- Diagnostic logging ---
        log_diagnostics(poll_count, &info);
    }
}

fn log_diagnostics(poll_count: u32, info: &MiMallocProcessInfo) {
    if !poll_count.is_multiple_of(LOG_INTERVAL) {
        return;
    }

    let stats = mem_stats::global();
    let relief = stats.pressure_cycles();
    let cells = stats.pressure_cells_unloaded();

    log::info!(
        "[MEM] RSS: {} | Peak: {} | Commit: {} | PeakCommit: {} | Faults: {:.1}/s | CPU eff: {:.0}%",
        info.memory_usage_human(),
        info.peak_memory_usage_human(),
        info.virtual_memory_usage_human(),
        libpsycho::common::helpers::format_bytes(info.get_peak_commit()),
        info.page_fault_rate_per_second(),
        info.cpu_efficiency_percent(),
    );

    let rate = GROWTH_RATE.load(Ordering::Relaxed);
    let pool_mb = super::pool::committed_bytes() / 1024 / 1024;
    let pool_live = super::pool::live_cells();
    let block_ct = super::block::block_count();
    log::info!(
        "[MEM] Pool: {}MB ({} live) | Blocks: {} | Rate: {}/s | Reliefs: {} | Cells: {}",
        pool_mb,
        pool_live,
        block_ct,
        format_rate(rate),
        relief,
        cells,
    );

    let cu_cells = super::engine::cell_unload::total_cells_unloaded();
    let cu_freed = super::engine::cell_unload::total_bytes_freed() / 1024 / 1024;
    if cu_cells > 0 {
        log::info!(
            "[RECLAIM] cell_unload: {} cells, freed {}MB",
            cu_cells,
            cu_freed,
        );
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

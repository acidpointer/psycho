//! Background memory watchdog thread.
//!
//! Polls mimalloc commit every 500ms, tracks growth rate via integer EMA,
//! and signals the main thread for cleanup when thresholds are exceeded.
//! Absorbs the diagnostic logging from the old monitor thread.
//!
//! The watchdog NEVER calls game functions (wrong thread). It only sets
//! atomic flags that the main thread reads at Phase 7 / AI_JOIN.
//!
//! Cleanup levels:
//!   Level 1 (normal):     HeapCompact 0-3 + drain large pool blocks
//!   Level 2 (aggressive): Level 1 + cell unload (deferred to AI_JOIN)
//!
//! During loading: thresholds are lowered by 200MB because the game
//! needs more VAS headroom for incoming cell data.

use std::sync::atomic::{AtomicI32, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use libmimalloc::process_info::MiMallocProcessInfo;

use super::engine::globals;
use super::pressure::PressureRelief;
use crate::mods::memory::heap_replacer::mem_stats;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Poll interval in milliseconds.
const POLL_MS: u32 = 500;

/// Diagnostic logging interval (every N polls = every N*POLL_MS ms).
/// 10 polls * 500ms = 5 seconds, matching the old monitor interval.
const LOG_INTERVAL: u32 = 10;

/// Growth thresholds above baseline commit.
const NORMAL_GROWTH: usize = 400 * 1024 * 1024;     // 400MB
const AGGRESSIVE_GROWTH: usize = 600 * 1024 * 1024;  // 600MB
const CRITICAL_GROWTH: usize = 800 * 1024 * 1024;    // 800MB

/// During loading, lower all thresholds by this amount.
const LOADING_THRESHOLD_REDUCTION: usize = 200 * 1024 * 1024; // 200MB

/// Minimum growth rate (bytes/sec) to trigger aggressive cleanup.
/// 2MB/s sustained growth means VAS will exhaust within minutes.
const AGGRESSIVE_RATE_THRESHOLD: i32 = 2 * 1024 * 1024;

/// Minimum milliseconds between aggressive (level 2) requests.
/// Lower = more frequent cell unload during gameplay = more headroom
/// before loading starts. 5s balances cleanup with NVSE plugin safety.
const AGGRESSIVE_COOLDOWN_MS: u64 = 5_000;

// ---------------------------------------------------------------------------
// Shared atomic state (read by main thread, written by watchdog)
// ---------------------------------------------------------------------------

/// Cleanup request level: 0=none, 1=normal, 2=aggressive.
static CLEANUP_REQUESTED: AtomicU8 = AtomicU8::new(0);

/// Smoothed commit growth rate in bytes/second (can be negative).
static GROWTH_RATE: AtomicI32 = AtomicI32::new(0);

/// Last commit sample for rate computation.
static LAST_COMMIT: AtomicUsize = AtomicUsize::new(0);

/// Timestamp of last aggressive request.
static LAST_AGGRESSIVE_MS: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Public API (called from main thread)
// ---------------------------------------------------------------------------

/// Take the current cleanup request (atomic swap to 0).
/// Returns 0 (none), 1 (normal), or 2 (aggressive).
pub fn take_cleanup_request() -> u8 {
    CLEANUP_REQUESTED.swap(0, Ordering::AcqRel)
}

/// Current smoothed growth rate in bytes/second.
pub fn current_growth_rate() -> i32 {
    GROWTH_RATE.load(Ordering::Relaxed)
}

/// True if commit exceeds baseline + CRITICAL_GROWTH.
/// Callable from any thread (OOM recovery path).
pub fn is_memory_critical() -> bool {
    let pr = match PressureRelief::instance() {
        Some(pr) => pr,
        None => return false,
    };
    let baseline = pr.baseline_commit();
    if baseline == 0 {
        return false;
    }
    let commit = MiMallocProcessInfo::get().get_current_commit();
    commit.saturating_sub(baseline) >= CRITICAL_GROWTH
}

// ---------------------------------------------------------------------------
// Watchdog thread
// ---------------------------------------------------------------------------

/// Background memory watchdog.
///
/// Spawns a thread that polls mimalloc commit, tracks growth rate,
/// and sets atomic flags for the main thread to consume at Phase 7.
/// Also performs periodic diagnostic logging (RSS, commit, faults).
pub struct Watchdog {
    run: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Watchdog {
    /// Spawn the watchdog thread. Returns a handle that stops the
    /// thread on drop.
    pub fn start() -> Self {
        let run = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let run_clone = run.clone();

        let handle = thread::Builder::new()
            .name("gheap-watchdog".into())
            .spawn(move || watchdog_loop(run_clone))
            .expect("failed to spawn watchdog thread");

        log::info!(
            "[WATCHDOG] Started (poll={}ms, normal={}MB, aggressive={}MB, critical={}MB)",
            POLL_MS,
            NORMAL_GROWTH / 1024 / 1024,
            AGGRESSIVE_GROWTH / 1024 / 1024,
            CRITICAL_GROWTH / 1024 / 1024,
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

fn watchdog_loop(run: Arc<std::sync::atomic::AtomicBool>) {
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
        let now_ms = info.get_elapsed_ms() as u64;

        // --- Rate tracking ---
        let prev_commit = LAST_COMMIT.swap(commit, Ordering::Relaxed);
        let first_sample = prev_commit == 0;
        let rate_sample = if !first_sample {
            // bytes per second: delta / (POLL_MS / 1000)
            let delta = commit as i64 - prev_commit as i64;
            (delta * 1000 / POLL_MS as i64) as i32
        } else {
            0
        };

        // Integer EMA: rate = (3 * sample + 7 * prev) / 10
        let smoothed = (3i64 * rate_sample as i64 + 7i64 * prev_rate as i64) / 10;
        prev_rate = smoothed as i32;
        GROWTH_RATE.store(prev_rate, Ordering::Relaxed);

        // --- Threshold evaluation ---
        let pr = match PressureRelief::instance() {
            Some(pr) => pr,
            None => {
                log_diagnostics(poll_count, &info);
                continue;
            }
        };

        let baseline = pr.baseline_commit();
        if baseline == 0 {
            log_diagnostics(poll_count, &info);
            continue;
        }

        let growth = commit.saturating_sub(baseline);
        let loading = globals::is_loading();

        // Lower thresholds during loading.
        let reduction = if loading { LOADING_THRESHOLD_REDUCTION } else { 0 };
        let normal_thresh = NORMAL_GROWTH.saturating_sub(reduction);
        let aggressive_thresh = AGGRESSIVE_GROWTH.saturating_sub(reduction);
        let critical_thresh = CRITICAL_GROWTH.saturating_sub(reduction);

        let mut level: u8 = 0;

        // Critical: always aggressive regardless of rate.
        if growth >= critical_thresh {
            level = 2;
        }
        // Aggressive: high growth AND fast rate.
        else if growth >= aggressive_thresh && prev_rate > AGGRESSIVE_RATE_THRESHOLD {
            level = 2;
        }
        // Normal: above threshold AND still growing (or first sample
        // where rate is unknown — don't miss a 500MB+ overshoot).
        else if growth >= normal_thresh && (prev_rate > 0 || first_sample) {
            level = 1;
        }

        // Aggressive cooldown.
        if level == 2 {
            let last_agg = LAST_AGGRESSIVE_MS.load(Ordering::Relaxed);
            if now_ms.saturating_sub(last_agg) < AGGRESSIVE_COOLDOWN_MS {
                level = 1; // downgrade to normal
            } else {
                LAST_AGGRESSIVE_MS.store(now_ms, Ordering::Relaxed);
            }
        }

        // Only escalate, never downgrade an existing request.
        if level > 0 {
            let _ = CLEANUP_REQUESTED.fetch_max(level, Ordering::Release);

            if level == 2 {
                log::warn!(
                    "[WATCHDOG] Aggressive cleanup: commit={}MB, growth={}MB, rate={}/s{}",
                    commit / 1024 / 1024,
                    growth / 1024 / 1024,
                    format_rate(prev_rate),
                    if loading { " (loading)" } else { "" },
                );
            } else {
                log::info!(
                    "[WATCHDOG] Normal cleanup: commit={}MB, growth={}MB, rate={}/s{}",
                    commit / 1024 / 1024,
                    growth / 1024 / 1024,
                    format_rate(prev_rate),
                    if loading { " (loading)" } else { "" },
                );
            }
        }

        // --- Diagnostic logging ---
        log_diagnostics(poll_count, &info);
    }
}

fn log_diagnostics(poll_count: u32, info: &MiMallocProcessInfo) {
    if poll_count % LOG_INTERVAL != 0 {
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
    let pool_mb = super::pool::pool_held_bytes() / 1024 / 1024;
    let evictions = super::pool::pool_evictions();
    let soft_bypasses = super::pool::pool_soft_bypasses();
    let bypass_active = super::allocator::is_bypass_active();
    log::info!(
        "[MEM] Pool: {}MB | Rate: {}/s | Reliefs: {} | Cells: {} | Evict: {} | SoftByp: {} | Bypass: {}",
        pool_mb,
        format_rate(rate),
        relief,
        cells,
        evictions,
        soft_bypasses,
        if bypass_active { "ON" } else { "off" },
    );

    let cu_cells = super::engine::cell_unload::total_cells_unloaded();
    let cu_freed = super::engine::cell_unload::total_bytes_freed() / 1024 / 1024;
    if cu_cells > 0 {
        log::info!(
            "[RECLAIM] cell_unload: {} cells, freed {}MB",
            cu_cells, cu_freed,
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

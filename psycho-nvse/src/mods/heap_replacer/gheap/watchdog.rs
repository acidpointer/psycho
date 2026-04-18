//! Background memory watchdog thread.
//!
//! Polls mimalloc commit every 250ms, tracks growth rate via integer EMA,
//! and runs lightweight cleanup directly on the background thread when
//! thresholds are exceeded. Absorbs the diagnostic logging from the old
//! monitor thread.
//!
//! Cleanup runs on the background thread (not main thread):
//!   havok_gc + mi_collect + slab::decommit_sweep
//!
//! All three operations are thread-safe:
//!   - havok_gc operates on hkMemorySystem, not the physics world
//!   - mi_collect(false) is a lazy sweep of per-thread heaps
//!   - decommit_sweep calls VirtualFree on fully-free pages
//!
//! Cell unloading is NOT performed by the watchdog. Cells only unload
//! during game-initiated transitions (the game handles its own bookkeeping)
//! and OOM emergencies (bypass=true path).
//!
//! During loading: cleanup is skipped entirely.

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};
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

/// Cleanup interval in milliseconds. Lightweight cleanup (havok_gc +
/// mi_collect + decommit_sweep) runs on the watchdog thread at this rate.
/// 5 seconds balances memory reclamation against overhead.
const CLEANUP_INTERVAL_MS: u64 = 5000;

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

/// Minimum growth rate (bytes/sec) to trigger aggressive cleanup.
/// 2MB/s sustained growth means VAS will exhaust within minutes.
const AGGRESSIVE_RATE_THRESHOLD: i32 = 2 * 1024 * 1024;

/// Minimum milliseconds between aggressive (level 2) requests.
/// 500ms prevents "cleanup storms" (death spiral) while keeping up with
/// stress testing (4x faster than the previous 2s default).
const AGGRESSIVE_COOLDOWN_MS: u64 = 500;

/// React time for normal cleanup rate floor calculation.
/// At the rate floor, sustained growth would reach VAS Critical in this many
/// seconds. 600s (10 min) gives ample time for cleanup before escalation.
const NORMAL_REACT_TIME_SECS: i64 = 600;

/// Minimum rate floor (bytes/sec) for normal cleanup. Prevents the floor
/// from dropping to zero at very tight headroom. 256KB/s is above typical
/// stable-gameplay noise but low enough for tight setups to remain responsive.
const MIN_NORMAL_RATE: i32 = 256 * 1024;

// ---------------------------------------------------------------------------
// Shared atomic state (read by main thread, written by watchdog)
// ---------------------------------------------------------------------------

/// Smoothed commit growth rate in bytes/second (can be negative).
static GROWTH_RATE: AtomicI32 = AtomicI32::new(0);

/// Last commit sample for rate computation.
static LAST_COMMIT: AtomicUsize = AtomicUsize::new(0);

/// Timestamp of last aggressive request.
static LAST_AGGRESSIVE_MS: AtomicU64 = AtomicU64::new(0);

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

#[allow(clippy::if_same_then_else)]
fn watchdog_loop(run: Arc<AtomicBool>) {
    let mut poll_count: u32 = 0;
    let mut prev_rate: i32 = 0;
    let mut last_cleanup_ms: u64 = 0;

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
        let loading = globals::is_loading();

        // Proportional thresholds: fraction of headroom, adapts to any modpack.
        // During loading, reduce thresholds by LOADING_THRESHOLD_REDUCTION.
        let headroom = super::allocator::get_headroom();
        let (growth, normal_thresh, aggressive_thresh, critical_thresh) = if baseline > 0
            && headroom > 0
        {
            let reduction = if loading {
                LOADING_THRESHOLD_REDUCTION
            } else {
                0
            };
            let g = commit.saturating_sub(baseline);
            let normal = ((headroom as f64 * NORMAL_GROWTH_PCT) as usize).saturating_sub(reduction);
            let aggressive =
                ((headroom as f64 * AGGRESSIVE_GROWTH_PCT) as usize).saturating_sub(reduction);
            let critical =
                ((headroom as f64 * CRITICAL_GROWTH_PCT) as usize).saturating_sub(reduction);
            (g, normal, aggressive, critical)
        } else if baseline > 0 {
            // Headroom not calibrated yet but baseline is. Use fallback.
            let reduction = if loading {
                LOADING_THRESHOLD_REDUCTION
            } else {
                0
            };
            let g = commit.saturating_sub(baseline);
            (
                g,
                NORMAL_GROWTH_FALLBACK.saturating_sub(reduction),
                AGGRESSIVE_GROWTH_FALLBACK.saturating_sub(reduction),
                CRITICAL_GROWTH_FALLBACK.saturating_sub(reduction),
            )
        } else {
            // Baseline not calibrated yet -- use absolute commit thresholds.
            let reduction = if loading {
                LOADING_THRESHOLD_REDUCTION
            } else {
                0
            };
            let normal_abs = FALLBACK_ABSOLUTE_THRESHOLD.saturating_sub(reduction);
            (
                commit, // growth = absolute commit when baseline=0
                normal_abs,
                normal_abs + 256 * 1024 * 1024, // +250MB for aggressive
                normal_abs + 500 * 1024 * 1024, // +500MB for critical
            )
        };

        // Measure free VAS once and reuse for rate floor + VAS-critical check.
        let free_vas = super::allocator::current_free_vas();

        // Dynamic rate floor for Normal cleanup: proportional to free VAS.
        // Lots of free VAS = high floor (relaxed). Low free VAS = low floor
        // (sensitive). Uses live measurement, adapts to any mod configuration.
        let rate_floor = if free_vas > super::allocator::VAS_CRITICAL_REMAINING {
            let margin = (free_vas - super::allocator::VAS_CRITICAL_REMAINING) as i64;
            (margin / NORMAL_REACT_TIME_SECS).max(MIN_NORMAL_RATE as i64) as i32
        } else {
            0 // at or below critical free VAS -- always clean
        };

        let mut level: u8 = 0;

        // --- VAS-critical bypass: fragmentation-induced OOM prevention ---
        // When free VAS drops below critical threshold, trigger aggressive
        // cleanup regardless of growth rate. This catches fragmentation
        // scenarios where commit is stable but available address space is
        // exhausted (no growth --> normal thresholds don't fire).
        if free_vas <= super::allocator::VAS_CRITICAL_REMAINING {
            log::warn!(
                "[WATCHDOG] VAS CRITICAL: free={}MB (threshold={}MB), forcing aggressive cleanup",
                free_vas / 1024 / 1024,
                super::allocator::VAS_CRITICAL_REMAINING / 1024 / 1024,
            );
            level = 2;
        }
        // Critical: aggressive only when commit is actively growing.
        #[allow(clippy::if_same_then_else)]
        if growth >= critical_thresh && prev_rate > AGGRESSIVE_RATE_THRESHOLD && !loading {
            level = 2;
        } else if growth >= critical_thresh && loading && prev_rate > 0 {
            level = 2;
        }
        // Aggressive: high growth AND fast rate.
        else if growth >= aggressive_thresh && prev_rate > AGGRESSIVE_RATE_THRESHOLD {
            level = 2;
        }
        // Normal: above threshold AND rate exceeds dynamic floor (or first
        // sample where rate is unknown -- don't miss a 500MB+ overshoot).
        else if growth >= normal_thresh && (prev_rate > rate_floor || first_sample) {
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

        // Skip cleanup during loading. The game's cell transition
        // already manages memory. Our cleanup could free objects the
        // transition still needs.
        if loading {
            log_diagnostics(poll_count, &info);
            continue;
        }

        // Run cleanup directly on the watchdog thread when:
        // - Pressure threshold is met (level > 0)
        // - AND cleanup interval has elapsed
        if level > 0 && now_ms.saturating_sub(last_cleanup_ms) >= CLEANUP_INTERVAL_MS {
            last_cleanup_ms = now_ms;

            if level == 2 {
                log::warn!(
                    "[WATCHDOG] Cleanup (level {}): commit={}MB, growth={}MB, rate={}/s",
                    level,
                    commit / 1024 / 1024,
                    growth / 1024 / 1024,
                    format_rate(prev_rate),
                );
            } else {
                log::info!(
                    "[WATCHDOG] Cleanup (level {}): commit={}MB, growth={}MB, rate={}/s, floor={}/s",
                    level,
                    commit / 1024 / 1024,
                    growth / 1024 / 1024,
                    format_rate(prev_rate),
                    format_rate(rate_floor),
                );
            }

            // Thread-safe cleanup. With pool/block the per-tier
            // allocators do not decommit, so the only reclaim levers
            // here are Havok GC and mi_collect (CRT arenas only).
            // Both are safe off the main thread.
            unsafe {
                globals::havok_gc(1);
                libmimalloc::mi_collect(false);
            }

            log::info!(
                "[WATCHDOG] Cleanup done: commit={}MB, pool={}MB, blocks={}",
                MiMallocProcessInfo::get().get_current_commit() / 1024 / 1024,
                super::pool::committed_bytes() / 1024 / 1024,
                super::block::block_count(),
            );
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

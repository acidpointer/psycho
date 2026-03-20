//! Unified memory statistics for all heap replacer subsystems.
//!
//! Single source of truth for memory diagnostics. Covers:
//! - mimalloc process-wide stats (RSS, commit, page faults)
//! - SBM2 scrap heap stats (region-level allocated bytes)
//! - Pressure relief stats (cycle count, cells unloaded)
//!
//! All counters are atomic -- safe to read from any thread (monitor,
//! console commands) and write from hot allocation paths.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use libmimalloc::process_info::MiMallocProcessInfo;
use libpsycho::common::helpers::format_bytes;

// ---------------------------------------------------------------------------
// MemStats
// ---------------------------------------------------------------------------

/// Unified memory statistics for the heap replacer.
pub struct MemStats {
    // -- Pressure relief counters --
    pressure_cycles: AtomicI64,
    pressure_cells_unloaded: AtomicI64,

    // -- SBM2 scrap heap counters --
    sbm2_allocated: AtomicU64,
}

/// Global singleton.
static INSTANCE: MemStats = MemStats::new();

impl MemStats {
    const fn new() -> Self {
        Self {
            pressure_cycles: AtomicI64::new(0),
            pressure_cells_unloaded: AtomicI64::new(0),
            sbm2_allocated: AtomicU64::new(0),
        }
    }

    // -- Pressure relief (written by pressure.rs) --

    /// Record a completed pressure relief cycle.
    pub fn record_pressure_relief(&self, cells: usize) {
        self.pressure_cycles.fetch_add(1, Ordering::Relaxed);
        if cells > 0 {
            self.pressure_cells_unloaded
                .fetch_add(cells as i64, Ordering::Relaxed);
        }
    }

    pub fn pressure_cycles(&self) -> i64 {
        self.pressure_cycles.load(Ordering::Relaxed)
    }

    pub fn pressure_cells_unloaded(&self) -> i64 {
        self.pressure_cells_unloaded.load(Ordering::Relaxed)
    }

    // -- SBM2 (written by sbm2 region alloc/free) --

    #[inline]
    pub fn sbm2_add(&self, size: u64) {
        self.sbm2_allocated.fetch_add(size, Ordering::Relaxed);
    }

    #[inline]
    pub fn sbm2_sub(&self, size: u64) {
        self.sbm2_allocated.fetch_sub(size, Ordering::Relaxed);
    }

    pub fn sbm2_allocated(&self) -> u64 {
        self.sbm2_allocated.load(Ordering::Relaxed)
    }

    // -- Queries --

    /// Short one-line summary for HUD notification.
    pub fn hud_summary() -> String {
        let info = MiMallocProcessInfo::get();
        let commit_mb = info.get_current_commit() / 1024 / 1024;
        let rss_mb = info.get_current_rss() / 1024 / 1024;
        format!("Memory: {}MB used, {}MB resident", commit_mb, rss_mb)
    }

    /// Detailed multi-line report for console.
    pub fn detailed_report() -> String {
        let info = MiMallocProcessInfo::get();
        let stats = global();

        let mut r = String::with_capacity(512);

        r.push_str("=== psycho-nvse Memory Report ===\n");
        r.push_str(&format!(
            "RSS:       {} (peak {})\n",
            info.memory_usage_human(),
            info.peak_memory_usage_human(),
        ));
        r.push_str(&format!(
            "Commit:    {} (peak {})\n",
            info.virtual_memory_usage_human(),
            format_bytes(info.get_peak_commit()),
        ));
        r.push_str(&format!(
            "SBM2:      {}\n",
            format_bytes(stats.sbm2_allocated() as usize),
        ));
        r.push_str(&format!(
            "Faults:    {} ({:.1}/s)\n",
            info.get_page_faults(),
            info.page_fault_rate_per_second(),
        ));
        r.push_str(&format!("CPU eff:   {:.0}%\n", info.cpu_efficiency_percent()));
        r.push_str(&format!(
            "Uptime:    {:.1}s\n",
            info.get_elapsed_ms() as f64 / 1000.0,
        ));

        let cycles = stats.pressure_cycles();
        if cycles > 0 {
            r.push_str(&format!(
                "Pressure:  {} cycles, {} cells freed\n",
                cycles,
                stats.pressure_cells_unloaded(),
            ));
        } else {
            r.push_str("Pressure:  no events\n");
        }

        r
    }
}

/// Get the global MemStats instance.
pub fn global() -> &'static MemStats {
    &INSTANCE
}

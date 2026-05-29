//! Unified memory statistics for all heap replacer subsystems.
//!
//! Single source of truth for memory diagnostics. Covers:
//! - active heap-replacer mode (full gheap vs light scrap_heap)
//! - gheap tier ownership and VAS fragmentation
//! - scrap_heap stats (region-level allocated bytes)
//! - Pressure relief stats (cycle count, cells unloaded)
//!
//! All counters are atomic -- safe to read from any thread (monitor,
//! console commands) and write from hot allocation paths.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use libpsycho::common::helpers::format_bytes;

use super::gheap::{block, pool, va_alloc, vas};
use super::{HeapReplacerMode, current_mode, scrap_heap};

// ---------------------------------------------------------------------------
// MemStats
// ---------------------------------------------------------------------------

/// Unified memory statistics for the heap replacer.
pub struct MemStats {
    // -- Pressure relief counters --
    pressure_cycles: AtomicI64,
    pressure_cells_unloaded: AtomicI64,

    // -- scrap_heap counters --
    scrap_heap_allocated: AtomicU64,
}

/// Global singleton.
static INSTANCE: MemStats = MemStats::new();

impl MemStats {
    const fn new() -> Self {
        Self {
            pressure_cycles: AtomicI64::new(0),
            pressure_cells_unloaded: AtomicI64::new(0),
            scrap_heap_allocated: AtomicU64::new(0),
        }
    }

    // -- Pressure relief (written by pressure.rs) --

    pub fn pressure_cycles(&self) -> i64 {
        self.pressure_cycles.load(Ordering::Relaxed)
    }

    pub fn pressure_cells_unloaded(&self) -> i64 {
        self.pressure_cells_unloaded.load(Ordering::Relaxed)
    }

    // -- scrap_heap (written by region alloc/free) --

    #[inline]
    pub fn scrap_heap_add(&self, size: u64) {
        self.scrap_heap_allocated.fetch_add(size, Ordering::Relaxed);
    }

    #[inline]
    pub fn scrap_heap_sub(&self, size: u64) {
        self.scrap_heap_allocated.fetch_sub(size, Ordering::Relaxed);
    }

    pub fn scrap_heap_allocated(&self) -> u64 {
        self.scrap_heap_allocated.load(Ordering::Relaxed)
    }

    // -- Queries --

    /// Short one-line summary for HUD notification.
    pub fn hud_summary() -> String {
        match current_mode() {
            Some(HeapReplacerMode::Full) => {
                let bytes = gheap_owned_bytes();
                let largest = vas::sample()
                    .map(|s| format!(", largest VAS {}MB", s.largest_free / vas::MB))
                    .unwrap_or_default();
                format!("gheap: {}{}", format_bytes(bytes), largest)
            }
            Some(HeapReplacerMode::Light) => {
                let s = scrap_heap::snapshot();
                format!(
                    "scrap_heap: {}, {} ids, {} regions",
                    format_bytes(s.live_bytes),
                    s.active_identities,
                    s.regions,
                )
            }
            None => "heap replacer: inactive".to_string(),
        }
    }

    /// Detailed multi-line report for console.
    pub fn detailed_report() -> String {
        match current_mode() {
            Some(HeapReplacerMode::Full) => Self::gheap_report(),
            Some(HeapReplacerMode::Light) => Self::scrap_heap_report(),
            None => "=== psycho-nvse Memory Report ===\nheap replacer: inactive\n".to_string(),
        }
    }

    fn gheap_report() -> String {
        let stats = global();
        let mut r = String::with_capacity(1024);

        let pool_commit = pool::committed_bytes();
        let pool_reserved = pool::reserved_bytes();
        let block_commit = block::committed_bytes();
        let va_live = va_alloc::live_bytes() as usize;
        let gheap_total = pool_commit
            .saturating_add(block_commit)
            .saturating_add(va_live);
        let scrap = scrap_heap::snapshot();

        r.push_str("=== psycho-nvse Memory Report: gheap ===\n");
        r.push_str("Mode:      FULL (gheap + scrap_heap)\n");
        r.push_str(&format!(
            "gheap:     {} owned by allocator tiers\n",
            format_bytes(gheap_total),
        ));
        r.push_str(&format!(
            "  pool:    {} committed / {} reserved, live_cells={}, deferred_free={}\n",
            format_bytes(pool_commit),
            format_bytes(pool_reserved),
            pool::live_cells(),
            pool::deferred_free_cells(),
        ));
        r.push_str(&format!(
            "  block:   {} committed, blocks={}\n",
            format_bytes(block_commit),
            block::block_count(),
        ));
        r.push_str(&format!(
            "  va:      {} live, blocks={}, allocs={}, frees={}, fails={}\n",
            format_bytes(va_live),
            va_alloc::live_count(),
            va_alloc::alloc_count(),
            va_alloc::free_count(),
            va_alloc::fail_count(),
        ));
        r.push_str(&format!(
            "scrap:     {}, ids={} active={} regions={} live_allocs={}\n",
            format_bytes(scrap.live_bytes),
            scrap.identities,
            scrap.active_identities,
            scrap.regions,
            scrap.live_allocs,
        ));
        r.push_str(&format!(
            "total:     {} gheap + scrap_heap\n",
            format_bytes(gheap_total.saturating_add(scrap.live_bytes)),
        ));

        if let Some(s) = vas::sample() {
            let largest_state = if s.largest_free < vas::CRITICAL_LARGEST_HOLE {
                "CRITICAL"
            } else {
                "ok"
            };
            r.push_str(&format!(
                "VAS:       free={} largest=0x{:08x}+{} second=0x{:08x}+{} holes={} ({})\n",
                format_bytes(s.total_free),
                s.largest_base,
                format_bytes(s.largest_free),
                s.second_base,
                format_bytes(s.second_free),
                s.holes,
                largest_state,
            ));
            r.push_str(&format!(
                "VAS map:   commit={} reserve={} regions={}\n",
                format_bytes(s.total_commit),
                format_bytes(s.total_reserve),
                s.regions,
            ));
        }

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

        let unload_cycles = super::gheap::engine::cell_unload::total_cycles();
        if unload_cycles > 0 {
            r.push_str(&format!(
                "Cell GC:   {} cells in {} cycles, freed {}\n",
                super::gheap::engine::cell_unload::total_cells_unloaded(),
                unload_cycles,
                format_bytes(super::gheap::engine::cell_unload::total_bytes_freed()),
            ));
        }

        r
    }

    fn scrap_heap_report() -> String {
        let s = scrap_heap::snapshot();
        let mut r = String::with_capacity(512);

        r.push_str("=== psycho-nvse Memory Report: scrap_heap ===\n");
        r.push_str("Mode:      LIGHT (scrap_heap only, gheap disabled)\n");
        r.push_str(&format!(
            "scrap:     {} live region capacity\n",
            format_bytes(s.live_bytes)
        ));
        r.push_str(&format!(
            "ids:       {} total, {} active\n",
            s.identities, s.active_identities
        ));
        r.push_str(&format!("regions:   {}\n", s.regions));
        r.push_str(&format!(
            "allocs:    {} live scrap allocations\n",
            s.live_allocs
        ));
        r.push_str("gheap:     disabled in light_mode\n");
        r
    }
}

/// Get the global MemStats instance.
pub fn global() -> &'static MemStats {
    &INSTANCE
}

pub fn current_allocator_bytes() -> usize {
    match current_mode() {
        Some(HeapReplacerMode::Full) => gheap_owned_bytes(),
        Some(HeapReplacerMode::Light) => scrap_heap::snapshot().live_bytes,
        None => 0,
    }
}

pub fn current_allocator_name() -> &'static str {
    match current_mode() {
        Some(HeapReplacerMode::Full) => "gheap",
        Some(HeapReplacerMode::Light) => "scrap_heap",
        None => "inactive",
    }
}

fn gheap_owned_bytes() -> usize {
    pool::committed_bytes()
        .saturating_add(block::committed_bytes())
        .saturating_add(va_alloc::live_bytes() as usize)
}

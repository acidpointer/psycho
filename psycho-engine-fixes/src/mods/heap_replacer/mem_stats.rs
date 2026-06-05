//! Unified memory statistics for all heap replacer subsystems.
//!
//! Single source of truth for memory diagnostics. Covers:
//! - active allocator mode
//! - gheap tier ownership and VAS fragmentation
//! - scrap_heap stats (region-level allocated bytes)
//! - Pressure relief stats (cycle count, cells unloaded)
//!
//! All counters are atomic -- safe to read from any thread (monitor,
//! console commands) and write from hot allocation paths.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use libpsycho::common::helpers::format_bytes;

use super::gheap::{block, pool, va_alloc, vas};
use super::{AllocatorMode, current_mode, scrap_heap};

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

    /// Detailed multi-line report for console.
    pub fn detailed_report() -> String {
        match current_mode() {
            Some(AllocatorMode::GheapAndScrapHeap) => Self::gheap_report(),
            Some(AllocatorMode::ScrapHeap) => Self::scrap_heap_report(),
            Some(AllocatorMode::Disabled) | None => Self::vanilla_report(),
        }
    }

    fn vanilla_report() -> String {
        let mut r = String::with_capacity(256);

        push_report_title(&mut r);
        r.push_str("Allocator: vanilla game allocator\n\n");

        push_section(&mut r, "Meaning");
        r.push_str("  Psycho heap replacement is disabled.\n");
        r.push_str("  No gheap or scrap_heap memory is owned by Psycho.\n");

        r
    }

    fn gheap_report() -> String {
        let stats = global();
        let mut r = String::with_capacity(1024);

        let pool_commit = pool::committed_bytes();
        let pool_reserved = pool::reserved_bytes();
        let block_commit = block::committed_bytes();
        let va_live = va_alloc::live_bytes() as usize;
        let gheap_total = gheap_owned_bytes();
        let scrap = scrap_heap::snapshot();

        push_report_title(&mut r);
        r.push_str("Allocator: gheap + scrap_heap\n\n");

        push_section(&mut r, "Status");
        if let Some(s) = vas::sample() {
            if s.largest_free < vas::CRITICAL_LARGEST_HOLE {
                r.push_str("  CRITICAL - address space is badly fragmented.\n");
                r.push_str(&format!(
                    "  Largest free block: {}\n",
                    format_bytes(s.largest_free)
                ));
                r.push_str("  Meaning: large texture/model loads may fail.\n\n");
            } else {
                r.push_str("  OK - address space still has room for big loads.\n");
                r.push_str(&format!(
                    "  Largest free block: {}\n\n",
                    format_bytes(s.largest_free)
                ));
            }
        } else {
            r.push_str("  Address space sample unavailable.\n\n");
        }

        push_section(&mut r, "Memory");
        r.push_str(&format!("  gheap total: {}\n", format_bytes(gheap_total),));
        r.push_str(&format!(
            "    pool:  {} committed, {} reserved\n",
            format_bytes(pool_commit),
            format_bytes(pool_reserved),
        ));
        r.push_str(&format!(
            "    block: {} committed in {} blocks\n",
            format_bytes(block_commit),
            block::block_count(),
        ));
        r.push_str(&format!(
            "    large: {} in {} direct blocks\n",
            format_bytes(va_live),
            va_alloc::live_count(),
        ));
        r.push_str(&format!(
            "  scrap_heap: {} in {} regions\n",
            format_bytes(scrap.live_bytes),
            scrap.regions,
        ));
        r.push_str(&format!(
            "  combined: {}\n\n",
            format_bytes(gheap_total.saturating_add(scrap.live_bytes)),
        ));

        push_section(&mut r, "Pool cells");
        r.push_str(&format!("  live pool cells: {}\n\n", pool::live_cells(),));

        let cycles = stats.pressure_cycles();
        push_section(&mut r, "Cleanup");
        if cycles > 0 {
            r.push_str(&format!(
                "  pressure relief: {} runs, {} cells unloaded\n",
                cycles,
                stats.pressure_cells_unloaded(),
            ));
        } else {
            r.push_str("  pressure relief: no runs yet\n");
        }

        r.push('\n');
        push_section(&mut r, "Advanced");
        r.push_str(&format!(
            "  direct allocs: {} alloc, {} free, {} failed\n",
            va_alloc::alloc_count(),
            va_alloc::free_count(),
            va_alloc::fail_count(),
        ));
        r.push_str(&format!(
            "  scrap ids: {} total, {} active\n",
            scrap.identities, scrap.active_identities,
        ));
        r.push_str(&format!(
            "  scrap live allocations: {}\n",
            scrap.live_allocs,
        ));
        if let Some(s) = vas::sample() {
            r.push_str(&format!(
                "  VAS free total: {}\n",
                format_bytes(s.total_free),
            ));
            r.push_str(&format!(
                "  VAS largest:  0x{:08x} + {}\n",
                s.largest_base,
                format_bytes(s.largest_free),
            ));
            r.push_str(&format!(
                "  VAS second:   0x{:08x} + {}\n",
                s.second_base,
                format_bytes(s.second_free),
            ));
            r.push_str(&format!(
                "  VAS map: {} commit, {} reserve, {} holes\n",
                format_bytes(s.total_commit),
                format_bytes(s.total_reserve),
                s.holes,
            ));
        }

        r
    }

    fn scrap_heap_report() -> String {
        let s = scrap_heap::snapshot();
        let mut r = String::with_capacity(512);

        push_report_title(&mut r);
        r.push_str("Allocator: scrap_heap only\n\n");

        push_section(&mut r, "Status");
        r.push_str("  OK - only temporary heaps are replaced.\n");
        r.push_str("  gheap is disabled, so main game heap stays vanilla.\n\n");

        push_section(&mut r, "Memory");
        r.push_str(&format!(
            "  scrap_heap: {} in {} regions\n",
            format_bytes(s.live_bytes),
            s.regions,
        ));
        r.push_str(&format!("  live allocations: {}\n\n", s.live_allocs,));

        push_section(&mut r, "Advanced");
        r.push_str(&format!(
            "  live region capacity: {}\n",
            format_bytes(s.live_bytes)
        ));
        r.push_str(&format!(
            "  identities: {} total, {} active\n",
            s.identities, s.active_identities
        ));
        r.push_str("  gheap: disabled\n");
        r
    }
}

fn push_report_title(out: &mut String) {
    out.push_str("================ PsychoInfo ================\n\n");
}

fn push_section(out: &mut String, title: &str) {
    out.push_str("==== ");
    out.push_str(title);
    out.push_str(" ====\n");
}

pub fn global() -> &'static MemStats {
    &INSTANCE
}

fn gheap_owned_bytes() -> usize {
    pool::committed_bytes()
        .saturating_add(block::committed_bytes())
        .saturating_add(va_alloc::live_bytes() as usize)
}

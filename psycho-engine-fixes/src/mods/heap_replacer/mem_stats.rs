//! Unified memory statistics for all heap replacer subsystems.
//!
//! Single source of truth for memory diagnostics. Covers:
//! - active allocator mode
//! - gheap tier ownership and VAS fragmentation
//! - scrap_heap stats (region-level allocated bytes)
//!
//! All counters are atomic -- safe to read from any thread (monitor,
//! console commands) and write from hot allocation paths.

use std::{
    fmt::Write as _,
    sync::atomic::{AtomicU64, Ordering},
};

use libpsycho::common::helpers::format_bytes;

use crate::mods::engine_fixes;

use super::gheap::{block, pool, va_alloc, vas};
use super::{AllocatorMode, current_mode, scrap_heap};

// ---------------------------------------------------------------------------
// MemStats
// ---------------------------------------------------------------------------

/// Unified memory statistics for the heap replacer.
pub struct MemStats {
    // -- scrap_heap counters --
    scrap_heap_allocated: AtomicU64,
}

/// Global singleton.
static INSTANCE: MemStats = MemStats::new();

impl MemStats {
    const fn new() -> Self {
        Self {
            scrap_heap_allocated: AtomicU64::new(0),
        }
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
        let mut report = match current_mode() {
            Some(AllocatorMode::GheapAndScrapHeap) => Self::gheap_report(),
            Some(AllocatorMode::ScrapHeap) => Self::scrap_heap_report(),
            Some(AllocatorMode::Disabled) | None => Self::vanilla_report(),
        };
        engine_fixes::append_diagnostic_report(&mut report);
        report
    }

    fn vanilla_report() -> String {
        let mut r = String::with_capacity(256);

        push_report_title(&mut r);
        push_value(&mut r, "Allocator", "Vanilla game heap");
        push_value(&mut r, "Memory health", "Managed by the game");

        push_section(&mut r, "Memory");
        r.push_str("  Psycho heap replacement is disabled.\n");
        r.push_str("  Engine fixes below remain independent.\n");

        r
    }

    fn gheap_report() -> String {
        let mut r = String::with_capacity(1024);

        let pool_commit = pool::committed_bytes();
        let pool_metadata = pool::metadata_bytes();
        let pool_metadata_reserved = pool::metadata_reserved_bytes();
        let pool_reserved = pool::reserved_bytes();
        let blocks = block::snapshot();
        let va_live = va_alloc::live_bytes() as usize;
        let gheap_total = gheap_owned_bytes();
        let scrap = scrap_heap::snapshot();

        push_report_title(&mut r);
        push_value(&mut r, "Allocator", "gheap + scrap heap");
        if let Some(s) = vas::sample() {
            if s.largest_free < vas::CRITICAL_LARGEST_HOLE {
                push_value(&mut r, "Memory health", "WARNING");
                push_value(&mut r, "Largest VAS", format_bytes(s.largest_free));
                r.push_str("  Large texture or model loads may fail.\n");
            } else {
                push_value(&mut r, "Memory health", "OK");
                push_value(&mut r, "Largest VAS", format_bytes(s.largest_free));
            }
        } else {
            push_value(&mut r, "Memory health", "VAS sample unavailable");
        }

        push_section(&mut r, "Memory");
        push_value(&mut r, "gheap total", format_bytes(gheap_total));
        push_value(
            &mut r,
            "Cell pools",
            format!(
                "{} live / {} reserved",
                format_bytes(pool_commit),
                format_bytes(pool_reserved),
            ),
        );
        push_value(
            &mut r,
            "Pool metadata",
            format!(
                "{} live / {} reserved",
                format_bytes(pool_metadata),
                format_bytes(pool_metadata_reserved),
            ),
        );
        push_value(
            &mut r,
            "Block heap",
            format!(
                "{} live / {} commit / {} slots",
                format_bytes(blocks.live_bytes),
                format_bytes(blocks.committed_bytes),
                blocks.slots
            ),
        );
        push_value(
            &mut r,
            "Large blocks",
            format!(
                "{} / {} live",
                format_bytes(va_live),
                va_alloc::live_count()
            ),
        );
        push_value(
            &mut r,
            "Scrap heap",
            format!(
                "{} / {} regions",
                format_bytes(scrap.live_bytes),
                scrap.regions
            ),
        );
        push_value(
            &mut r,
            "Combined",
            format_bytes(gheap_total.saturating_add(scrap.live_bytes)),
        );

        push_section(&mut r, "Activity");
        push_value(&mut r, "Pool cells", format!("{} live", pool::live_cells()));
        push_value(
            &mut r,
            "Direct allocs",
            format!(
                "{} made / {} freed / {} failed",
                va_alloc::alloc_count(),
                va_alloc::free_count(),
                va_alloc::fail_count(),
            ),
        );
        push_value(
            &mut r,
            "Scrap activity",
            format!(
                "{} allocs / {} IDs / {} active",
                scrap.live_allocs, scrap.identities, scrap.active_identities
            ),
        );
        let overflow_user = pool::overflow_user_reserved_bytes();
        let overflow_metadata = pool::overflow_metadata_reserved_bytes();
        if overflow_user != 0 || overflow_metadata != 0 {
            push_value(
                &mut r,
                "Overflow reserve",
                format!(
                    "{} user / {} meta",
                    format_bytes(overflow_user),
                    format_bytes(overflow_metadata),
                ),
            );
        }

        if let Some(s) = vas::sample() {
            push_section(&mut r, "Address space");
            push_value(&mut r, "Free total", format_bytes(s.total_free));
            push_value(
                &mut r,
                "Largest hole",
                format!("{} at {:08X}", format_bytes(s.largest_free), s.largest_base),
            );
            push_value(&mut r, "Committed", format_bytes(s.total_commit));
            push_value(&mut r, "Reserved", format_bytes(s.total_reserve));
            push_value(&mut r, "Free holes", s.holes);
        }

        r
    }

    fn scrap_heap_report() -> String {
        let s = scrap_heap::snapshot();
        let mut r = String::with_capacity(512);

        push_report_title(&mut r);
        push_value(&mut r, "Allocator", "Scrap heap only");
        push_value(&mut r, "Memory health", "OK");

        push_section(&mut r, "Memory");
        push_value(&mut r, "Scrap heap", format_bytes(s.live_bytes));
        push_value(&mut r, "Regions", s.regions);
        push_value(&mut r, "Live allocs", s.live_allocs);
        push_value(
            &mut r,
            "Identities",
            format!("{} total / {} active", s.identities, s.active_identities),
        );
        r.push_str("  Main game heap remains vanilla.\n");
        r
    }
}

fn push_report_title(out: &mut String) {
    out.push_str("============================================\n");
    out.push_str("            PSYCHO ENGINE FIXES\n");
    out.push_str("============================================\n");
}

fn push_section(out: &mut String, title: &str) {
    out.push('\n');
    out.push_str(title);
    out.push('\n');
    out.push_str("--------------------------------------------\n");
}

fn push_value(out: &mut String, label: &str, value: impl std::fmt::Display) {
    let _ = writeln!(out, "  {label:<18}{value}");
}

pub fn global() -> &'static MemStats {
    &INSTANCE
}

fn gheap_owned_bytes() -> usize {
    pool::committed_bytes()
        .saturating_add(pool::metadata_bytes())
        .saturating_add(block::committed_bytes())
        .saturating_add(va_alloc::live_bytes() as usize)
}

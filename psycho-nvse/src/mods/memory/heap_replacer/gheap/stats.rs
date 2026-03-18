//! Game heap allocation statistics.
//!
//! Tracks alloc/free balance for leak detection. Read by the monitor thread.

use std::sync::atomic::{AtomicI64, Ordering};

pub struct GheapStats {
    balance: AtomicI64,
    alloc_count: AtomicI64,
    free_count: AtomicI64,
}

impl GheapStats {
    pub const fn new() -> Self {
        Self {
            balance: AtomicI64::new(0),
            alloc_count: AtomicI64::new(0),
            free_count: AtomicI64::new(0),
        }
    }

    #[inline]
    pub fn on_alloc(&self) -> i64 {
        self.balance.fetch_add(1, Ordering::Relaxed);
        self.alloc_count.fetch_add(1, Ordering::Relaxed)
    }

    #[inline]
    pub fn on_free(&self) {
        self.balance.fetch_sub(1, Ordering::Relaxed);
        self.free_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn balance(&self) -> i64 {
        self.balance.load(Ordering::Relaxed)
    }

    pub fn alloc_count(&self) -> i64 {
        self.alloc_count.load(Ordering::Relaxed)
    }

    pub fn free_count(&self) -> i64 {
        self.free_count.load(Ordering::Relaxed)
    }
}

/// Global instance — used by hooks and monitor thread.
static INSTANCE: GheapStats = GheapStats::new();

pub fn instance() -> &'static GheapStats {
    &INSTANCE
}

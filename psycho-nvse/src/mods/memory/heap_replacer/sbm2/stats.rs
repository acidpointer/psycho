use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct AllocatorStats {
    /// Total allocated memory for all regions
    total_allocated_mem: AtomicU64,
}

impl AllocatorStats {
    pub fn new() -> Self {
        Self {
            total_allocated_mem: AtomicU64::new(0),
        }
    }

    #[inline]
    pub(super) fn add_total_alloc_mem(&self, size: u64) -> u64 {
        self.total_allocated_mem.fetch_add(size, Ordering::Relaxed)
    }

    #[inline]
    pub(super) fn sub_total_alloc_mem(&self, size: u64) -> u64 {
        self.total_allocated_mem.fetch_sub(size, Ordering::Relaxed)
    }

    #[inline]
    pub fn get_total_alloc_mem(&self) -> u64 {
        self.total_allocated_mem.load(Ordering::Relaxed)
    }
}

//! Game heap replacement: two-tier zombie-safe allocator.
//!
//! Primary tier: `pool` (fixed-size cells, NVHR-style mheap port).
//! Secondary tier: `block` (variable-size cells, NVHR-style dheap port).
//! Huge allocations: `va_alloc` (direct VirtualAlloc).
//! Fallback: original SBM trampoline (never-NULL contract).

pub mod allocator;
pub mod block;
pub mod crash_diag;
pub mod engine;
pub mod game_guard;
pub mod havok_fix;
pub mod heap_manager;
pub mod hooks;
pub mod memset_fix;
pub mod pool;
pub mod pressure;
pub mod statics;
pub mod texture_cache;
pub mod types;
pub mod va_alloc;
pub mod watchdog;

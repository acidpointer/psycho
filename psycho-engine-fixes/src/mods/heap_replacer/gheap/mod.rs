//! Game heap replacement: size-dispatched allocator.
//!
//! Primary tier: `pool` (fixed-size cells, NVHR-style mheap port).
//! Secondary tier: `block` (variable-size cells, NVHR-style dheap port).
//! Huge allocations: `va_alloc` (direct VirtualAlloc).
//! Exhaustion: return NULL after every owned tier fails; re-entering the
//! original SBM would recurse through the hooked CRT allocation path.

pub mod allocator;
pub mod block;
pub mod engine;
pub mod game_guard;
pub mod hang;
pub mod hitch;
pub mod hooks;
pub mod model_task_fix;
pub mod pool;
pub mod pressure;
pub mod statics;
pub mod texture_cache;
pub mod types;
pub mod va_alloc;
pub mod vanilla_large_heap;
pub mod vas;
pub mod watchdog;

//! Game heap replacement module.
//!
//! Replaces the game's GameHeap allocator with mimalloc and provides
//! engine fixes for stale pointer issues that arise from mimalloc's
//! fast memory recycling (vs SBM's zombie data behavior).

mod alloc;
pub mod cell_transition;
pub mod hooks;
pub mod io_task;
pub mod monitor;
pub mod pressure;
pub mod queued_ref;
pub mod skeleton_update;
pub mod statics;
pub mod texture_cache;
pub mod types;

#[allow(unused_imports)]
pub use alloc::Gheap;

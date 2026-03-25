//! Game heap replacement module.
//!
//! Replaces the game's GameHeap allocator with mimalloc and provides
//! engine fixes for stale pointer issues that arise from mimalloc's
//! fast memory recycling (vs SBM's zombie data behavior).

pub mod actor_process_hooks;
pub mod cell_transition;
pub mod engine;
pub mod game_guard;
pub mod havok_hooks;
pub mod hooks;
pub mod io_task;
pub mod monitor;
pub mod orchestrator;
pub mod pdd_hook;
pub mod pressure;
pub mod skeleton_update;
pub mod statics;
pub mod texture_cache;
pub mod types;

pub use orchestrator::HeapOrchestrator;

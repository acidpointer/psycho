//! Game heap replacement with per-thread zombie pools.
//!
//! Replaces the game's SBM pool allocator (FUN_00aa3e40 / FUN_00aa4060)
//! with a slab allocator + VirtualAlloc backend. Every thread gets a
//! thread-local pool that holds freed blocks on per-size-class freelists.
//! This preserves SBM's "freed memory stays readable" contract -- stale
//! readers find valid zombie data instead of recycled garbage.
//!
//! Design:
//!   alloc  -> slab freelist (hit) or slab commit (miss)
//!   free   -> slab freelist push (block stays readable, zombie)
//!   OOM    -> slab decommit + game OOM stages (mutex) + retry

pub mod allocator;
pub mod engine;
pub mod game_guard;
pub mod heap_manager;
pub mod hooks;
pub mod pdd_hook;
pub mod pressure;
pub mod procmon;
pub mod slab;
pub mod statics;
pub mod texture_cache;
pub mod types;
pub mod watchdog;

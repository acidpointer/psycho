//! Heap replacer module for Fallout New Vegas.
//!
//! Replaces the game's heap and scrap heap allocators with mimalloc.

pub mod crt;
pub mod game_heap;
pub mod gheap;
pub mod heap_validate;
mod install;
#[allow(dead_code)]
pub mod mem_stats;
pub mod scrap_heap;

pub use install::{install_game_heap_hooks, start_deferred_threads};

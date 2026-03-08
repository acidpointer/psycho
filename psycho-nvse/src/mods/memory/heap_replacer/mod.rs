//! Heap replacer module for Fallout New Vegas.
//!
//! Replaces the game's heap and scrap heap allocators with MiMalloc and bump allocators.
//! Based on https://github.com/iranrmrf/Heap-Replacer


mod hooks;
mod types;
mod replacer;
mod small_blocks_allocator;

pub use replacer::install_game_heap_hooks;



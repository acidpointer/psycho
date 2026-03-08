//! Heap replacer module for Fallout New Vegas.
//!
//! Replaces the game's heap and scrap heap allocators with MiMalloc and bump allocators.
//! Based on https://github.com/iranrmrf/Heap-Replacer


mod hooks;
mod types;
mod replacer;
mod small_blocks_allocator;

pub use replacer::install_game_heap_hooks;

/// Game heap function addresses (Fallout New Vegas)
pub(super) const GAME_HEAP_ALLOCATE_ADDR: usize = 0x00AA3E40;
pub(super) const GAME_HEAP_REALLOCATE_ADDR_1: usize = 0x00AA4150;
pub(super) const GAME_HEAP_REALLOCATE_ADDR_2: usize = 0x00AA4200;
pub(super) const GAME_HEAP_MSIZE_ADDR: usize = 0x00AA44C0;
pub(super) const GAME_HEAP_FREE_ADDR: usize = 0x00AA4060;


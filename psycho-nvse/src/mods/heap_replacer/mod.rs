//! Heap replacer module for Fallout New Vegas.
//!
//! Replaces the game's heap and scrap heap allocators with mimalloc.

mod crt_iat;
mod crt_inline;
mod mimalloc;
pub mod gheap;
pub mod heap_validate;
mod install;
pub mod mem_stats;
pub mod scrap_heap;

pub use install::{heap_replacer_activate, heap_replacer_initialize};
pub use mimalloc::{configure_mimalloc, configure_mimalloc_with_arena};
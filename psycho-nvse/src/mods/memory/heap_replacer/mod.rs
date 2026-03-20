//! Heap replacer module for Fallout New Vegas.
//!
//! Replaces the game's heap and scrap heap allocators with mimalloc.

pub mod gheap;
pub mod heap_validate;
mod hooks;
#[allow(dead_code)]
pub mod mem_stats;
mod types;
pub mod replacer;
pub mod sbm2;

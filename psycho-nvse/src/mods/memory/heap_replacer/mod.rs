//! Heap replacer module for Fallout New Vegas.
//!
//! Replaces the game's heap and scrap heap allocators with mimalloc.

pub mod heap_validate;
mod hooks;
mod types;
pub mod replacer;
pub mod sbm;
pub mod sbm2;

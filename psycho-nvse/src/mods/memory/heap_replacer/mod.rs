//! Heap replacer module for Fallout New Vegas.
//!
//! Replaces the game's heap and scrap heap allocators with MiMalloc and bump allocators.
//! Based on https://github.com/iranrmrf/Heap-Replacer


mod hooks;
mod types;
pub mod replacer;
pub mod sbm;

pub mod sbm2;



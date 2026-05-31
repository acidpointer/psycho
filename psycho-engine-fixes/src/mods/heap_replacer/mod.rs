//! Heap replacer module for Fallout New Vegas.
//!
//! Replaces the game's heap and scrap heap allocators. The user-facing
//! `memory.allocator` config controls whether this module is disabled,
//! runs scrap_heap only, or runs gheap plus scrap_heap.

mod crt_iat;
mod crt_inline;
pub mod gheap;
pub mod heap_validate;
mod install;
pub mod mem_stats;
mod mimalloc;
mod mode;
pub mod scrap_heap;

pub use install::{
    install_gheap_hooks, install_gheap_initialize, install_sheap_hooks, install_sheap_initialize,
};
pub use mimalloc::initialize_mimalloc;
pub use mode::{AllocatorMode, current_mode, decide_mode};

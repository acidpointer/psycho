//! Heap replacer module for Fallout New Vegas.
//!
//! Replaces the game's heap and scrap heap allocators. Can run in
//! "full" mode (gheap + scrap_heap) or "light" mode (scrap_heap only)
//! depending on config and measured baseline commit -- see `mode`.

mod crt_iat;
mod crt_inline;
mod mimalloc;
pub mod gheap;
pub mod heap_validate;
mod install;
pub mod mem_stats;
mod mode;
pub mod scrap_heap;

pub use install::{
    install_gheap_activate, install_gheap_initialize, install_sheap_activate,
    install_sheap_initialize,
};
pub use mimalloc::configure_mimalloc;
pub use mode::{HeapReplacerMode, current_mode, decide_mode};

//! Heap-replacer mode selection: full gheap+sheap vs light (sheap only).
//!
//! Full mode runs the entire allocator replacement: gheap (game heap /
//! CRT / OOM handling / havok instrumentation) plus the scrap-heap
//! runtime. Light mode runs only the scrap-heap runtime and its single
//! required patch. Picked once at Preload from the user's config flag,
//! cached for the rest of the process lifetime so Preload and Load
//! agree.
//!
//! Light mode exists for heavy modlists whose baseline commit at our
//! Preload is already past what gheap's trampoline + lazy reservation
//! machinery can survive. The scrap-heap side is cheap (six hooks, one
//! 30-byte NOP) and is the single biggest stability win for mod-heavy
//! setups, so preserving it while dropping gheap is the pragmatic
//! middle ground.

use std::sync::OnceLock;

use crate::config::MemoryConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapReplacerMode {
    Full,
    Light,
}

static MODE: OnceLock<HeapReplacerMode> = OnceLock::new();

/// Resolve the mode from config, cache it, and return the cached value.
/// Safe to call once; subsequent calls return the cached choice
/// regardless of argument changes.
pub fn decide_mode(cfg: &MemoryConfig) -> HeapReplacerMode {
    *MODE.get_or_init(|| {
        if cfg.light_mode {
            log::info!("[HEAP REPLACER] light_mode=true -> LIGHT mode");
            HeapReplacerMode::Light
        } else {
            log::info!("[HEAP REPLACER] light_mode=false -> FULL mode");
            HeapReplacerMode::Full
        }
    })
}

/// Read the cached mode. Returns `None` if `decide_mode` hasn't run yet.
pub fn current_mode() -> Option<HeapReplacerMode> {
    MODE.get().copied()
}

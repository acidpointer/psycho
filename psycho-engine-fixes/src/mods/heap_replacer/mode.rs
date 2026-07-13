//! Heap allocator mode selection.
//!
//! Picked once from `memory.allocator`, then cached for the rest of the
//! process lifetime so every allocator path agrees.

use std::sync::{
    OnceLock,
    atomic::{AtomicU8, Ordering},
};

use crate::config::MemoryConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocatorMode {
    Disabled,
    ScrapHeap,
    GheapAndScrapHeap,
}

impl AllocatorMode {
    pub fn from_config_value(value: u8) -> Self {
        match value {
            0 => Self::Disabled,
            1 => Self::ScrapHeap,
            2 => Self::GheapAndScrapHeap,
            other => {
                log::warn!(
                    "[MEMORY] Unknown allocator={} in config; using 2 (gheap + scrap_heap)",
                    other
                );
                Self::GheapAndScrapHeap
            }
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Disabled => "vanilla",
            Self::ScrapHeap => "scrap_heap",
            Self::GheapAndScrapHeap => "gheap + scrap_heap",
        }
    }

    pub fn config_value(self) -> u8 {
        match self {
            Self::Disabled => 0,
            Self::ScrapHeap => 1,
            Self::GheapAndScrapHeap => 2,
        }
    }
}

static REQUESTED_MODE: OnceLock<AllocatorMode> = OnceLock::new();
static ACTIVE_MODE: AtomicU8 = AtomicU8::new(u8::MAX);

/// Resolve the mode from config, cache it, and return the cached value.
/// Safe to call once; subsequent calls return the cached choice
/// regardless of argument changes.
pub fn decide_mode(cfg: &MemoryConfig) -> AllocatorMode {
    *REQUESTED_MODE.get_or_init(|| {
        let mode = AllocatorMode::from_config_value(cfg.allocator);
        log::info!(
            "[MEMORY] allocator={} -> {}",
            mode.config_value(),
            mode.name()
        );
        mode
    })
}

/// Return the mode that actually committed.
///
/// This remains `None` while startup is still deciding or preparing a mode,
/// even if the configuration requested allocator replacement.
pub fn current_mode() -> Option<AllocatorMode> {
    match ACTIVE_MODE.load(Ordering::Acquire) {
        0 => Some(AllocatorMode::Disabled),
        1 => Some(AllocatorMode::ScrapHeap),
        2 => Some(AllocatorMode::GheapAndScrapHeap),
        _ => None,
    }
}

pub(crate) fn set_active_mode(mode: AllocatorMode) {
    ACTIVE_MODE.store(mode.config_value(), Ordering::Release);
}

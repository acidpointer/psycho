//! psycho-nvse configuration
//!
//! TOML-based configuration for toggling individual patches.
//! On first run, a default config file is created at `./psycho-nvse.toml`
//! with all patches enabled. Users can edit the file and restart the game
//! to selectively disable patches for troubleshooting.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use libpsycho::config::Config;

/// Default config file path (standard NVSE plugin directory).
const CONFIG_PATH: &str = "Data/NVSE/Plugins/psycho-nvse.toml";

/// Global config singleton, loaded once at startup.
static CONFIG: OnceLock<PsychoConfig> = OnceLock::new();

/// Top-level configuration for psycho-nvse.
#[derive(Debug, Deserialize, Serialize)]
pub struct PsychoConfig {
    /// General settings.
    pub general: GeneralConfig,

    /// Memory allocator patches (mimalloc, heap replacement, scrap heap).
    pub memory: MemoryConfig,

    /// Performance optimization patches.
    pub perf: PerfConfig,

    /// Stability guard patches (null dereference protection).
    pub stability: StabilityConfig,

    /// Zlib replacement (libz-rs).
    pub zlib: ZlibConfig,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GeneralConfig {
    /// Open a Windows console window for real-time log output.
    pub console: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MemoryConfig {
    /// Replace CRT allocator (malloc/free/etc.) with mimalloc via IAT hooks.
    pub crt_hooks: bool,

    /// Replace game heap (GameHeap::Allocate/Free) with mimalloc via inline hooks.
    pub game_heap_hooks: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PerfConfig {
    /// Set Windows timer resolution to 1ms (timeBeginPeriod).
    pub timer_resolution: bool,

    /// Boost main thread priority to ABOVE_NORMAL and opt out of power throttling.
    pub thread_priority: bool,

    /// Add spin count (4096) to all game critical sections.
    pub critical_section_spin: bool,

    /// Reduce I/O polling Sleep durations (50/10ms -> 1ms).
    pub sleep_patches: bool,

    /// Reduce deferred task queue overflow budget (1000ms -> 100ms).
    pub deferred_task_budget: bool,

    /// Throttle per-frame detection/actor updates to every 2nd frame.
    pub detection_budget: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StabilityConfig {
    /// Guard FUN_0044DDC0 (AI path getter) against null pointer dereference.
    pub null_deref_guards: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ZlibConfig {
    /// Replace zlib 1.2.3 with libz-rs 1.3.1.
    pub enabled: bool,
}

impl Default for PsychoConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                console: false,
            },
            memory: MemoryConfig {
                crt_hooks: true,
                game_heap_hooks: true,
            },
            perf: PerfConfig {
                timer_resolution: true,
                thread_priority: true,
                critical_section_spin: true,
                sleep_patches: true,
                deferred_task_budget: true,
                detection_budget: true,
            },
            stability: StabilityConfig {
                null_deref_guards: true,
            },
            zlib: ZlibConfig {
                enabled: true,
            },
        }
    }
}

/// Load the global configuration. Call once at startup.
///
/// Creates a default `psycho-nvse.toml` if it doesn't exist.
/// Falls back to defaults on any error (logs the error but doesn't crash).
pub fn load_config() -> &'static PsychoConfig {
    CONFIG.get_or_init(|| {
        match Config::load_or_default::<PsychoConfig>(CONFIG_PATH) {
            Ok(cfg) => {
                log::info!("[CONFIG] Loaded from '{}'", CONFIG_PATH);
                cfg
            }
            Err(err) => {
                log::error!(
                    "[CONFIG] Failed to load '{}': {:?}. Using defaults.",
                    CONFIG_PATH,
                    err
                );
                PsychoConfig::default()
            }
        }
    })
}

/// Get the global config reference. Returns an error if `load_config()` hasn't been called.
pub fn get_config() -> anyhow::Result<&'static PsychoConfig> {
    CONFIG
        .get()
        .ok_or_else(|| anyhow::anyhow!("Config not loaded - call load_config() first"))
}

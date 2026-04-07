//! psycho-nvse configuration
//!
//! TOML-based configuration with automatic schema migration.
//! Uses `libpsycho::config::Config::load_or_migrate` — missing fields
//! get defaults, removed fields get pruned, file synced on load.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use libpsycho::config::Config;

const CONFIG_PATH: &str = "Data/NVSE/Plugins/psycho-nvse.toml";

static CONFIG: OnceLock<PsychoConfig> = OnceLock::new();

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct PsychoConfig {
    pub general: GeneralConfig,
    pub memory: MemoryConfig,
    pub perf: PerfConfig,
    pub zlib: ZlibConfig,
    pub display: DisplayConfig,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
#[derive(Default)]
pub struct GeneralConfig {
    /// Open a Windows console window for real-time log output.
    pub console: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct MemoryConfig {
    /// Replace CRT allocator (malloc/free/etc.) with mimalloc via IAT hooks.
    pub crt_hooks: bool,
    /// Replace game heap (GameHeap::Allocate/Free) with mimalloc via inline hooks.
    pub game_heap_hooks: bool,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            crt_hooks: true,
            game_heap_hooks: true,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct PerfConfig {
    /// Replace the game's Mersenne Twister RNG with modern SmallRng (WyRand).
    pub rng: bool,
}

impl Default for PerfConfig {
    fn default() -> Self {
        Self { rng: true }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct ZlibConfig {
    /// Replace zlib 1.2.3 with libz-rs 1.3.1.
    pub enabled: bool,
}

impl Default for ZlibConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct DisplayConfig {
    /// Force borderless fullscreen mode (fixes alt-tab with DXVK).
    /// Replaces OneTweak -- uninstall OneTweak when this is enabled.
    pub borderless: bool,
}

impl Default for DisplayConfig {
    fn default() -> Self {
        Self { borderless: true }
    }
}

/// Load the global configuration (read-only, no file write-back).
///
/// Safe to call under the Windows loader lock (DllMain). Only does a single
/// file read + TOML parse. Call [`sync_config`] later to write-back schema
/// changes.
pub fn load_config() -> &'static PsychoConfig {
    CONFIG.get_or_init(|| {
        let cfg = Config::load_readonly::<PsychoConfig>(CONFIG_PATH);
        log::info!("[CONFIG] Loaded (read-only)");
        cfg
    })
}

/// Write config to disk if schema changed (adds missing fields, prunes stale).
///
/// Must be called OUTSIDE DllMain (no loader lock). Typically from
/// NVSEPlugin_Load.
pub fn sync_config() {
    if let Some(cfg) = CONFIG.get() {
        Config::sync_to_disk(CONFIG_PATH, cfg);
    }
}

/// Get the global config reference.
pub fn get_config() -> anyhow::Result<&'static PsychoConfig> {
    CONFIG
        .get()
        .ok_or_else(|| anyhow::anyhow!("Config not loaded - call load_config() first"))
}

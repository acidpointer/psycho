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

/// Load the global configuration with automatic schema migration.
pub fn load_config() -> &'static PsychoConfig {
    CONFIG.get_or_init(|| {
        let cfg = Config::load_or_migrate::<PsychoConfig>(CONFIG_PATH);
        log::info!("[CONFIG] Ready");
        cfg
    })
}

/// Get the global config reference.
pub fn get_config() -> anyhow::Result<&'static PsychoConfig> {
    CONFIG
        .get()
        .ok_or_else(|| anyhow::anyhow!("Config not loaded - call load_config() first"))
}

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
    pub logger: LoggerConfig,
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
#[derive(Default)]
pub struct LoggerConfig {
    /// Use debug logs
    pub debug: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct MemoryConfig {
    /// Replace game heap and all memory management
    pub heap_replacer: bool,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            heap_replacer: true,
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
    /// Zlib replacer
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
    /// Enable display tweaks.
    /// Mostly covers alt-tab issues.
    pub tweaks: bool,
}

impl Default for DisplayConfig {
    fn default() -> Self {
        Self { tweaks: true }
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

/// Get the global config reference.
pub fn get_config() -> anyhow::Result<&'static PsychoConfig> {
    CONFIG
        .get()
        .ok_or_else(|| anyhow::anyhow!("Config not loaded - call load_config() first"))
}

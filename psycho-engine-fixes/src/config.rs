//! psycho configuration
//!
//! TOML-based runtime configuration.

use std::{path::Path, sync::OnceLock};

use serde::{Deserialize, Deserializer, Serialize};

use libpsycho::config::Config;

const CONFIG_PATH: &str = "mods/psycho_engine_fixes.toml";
const LEGACY_CONFIG_PATHS: &[&str] = &[
    "mods/psycho.toml",
    "Data/NVSE/Plugins/psycho.toml",
    "Data/NVSE/Plugins/psycho-nvse.toml",
];

static CONFIG: OnceLock<PsychoConfig> = OnceLock::new();

#[derive(Debug, Serialize)]
pub struct PsychoConfig {
    pub memory: MemoryConfig,
    pub engine_fixes: EngineFixesConfig,
    pub performance: PerformanceConfig,
    pub diagnostics: DiagnosticsConfig,
}

impl Default for PsychoConfig {
    fn default() -> Self {
        Self {
            memory: MemoryConfig::default(),
            engine_fixes: EngineFixesConfig::default(),
            performance: PerformanceConfig::default(),
            diagnostics: DiagnosticsConfig::default(),
        }
    }
}

impl<'de> Deserialize<'de> for PsychoConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawPsychoConfig::deserialize(deserializer)?;
        let legacy_display_tweaks = raw.performance.as_ref().and_then(|p| p.display_tweaks);
        Ok(Self {
            memory: MemoryConfig::from_raw(raw.memory),
            engine_fixes: EngineFixesConfig::from_raw(
                raw.engine_fixes,
                legacy_display_tweaks,
                raw.display,
            ),
            performance: PerformanceConfig::from_raw(raw.performance, raw.perf, raw.zlib),
            diagnostics: DiagnosticsConfig::from_raw(raw.diagnostics, raw.general, raw.logger),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct MemoryConfig {
    /// 0 = vanilla heap, 1 = scrap_heap, 2 = gheap + scrap_heap.
    pub allocator: u8,
    /// Guard known stale gheap task cleanup paths.
    pub gheap_task_safety: bool,
    /// Optional legacy full PDD purge. Keep off unless testing.
    pub gheap_periodic_pdd_purge: bool,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            allocator: 2,
            gheap_task_safety: true,
            gheap_periodic_pdd_purge: false,
        }
    }
}

impl MemoryConfig {
    fn from_raw(raw: RawMemoryConfig) -> Self {
        let default = Self::default();
        let allocator = raw.allocator.unwrap_or_else(|| {
            if let Some(enabled) = raw.legacy_heap_replacer {
                if !enabled {
                    0
                } else if raw.legacy_scrap_heap_only.unwrap_or(false) {
                    1
                } else {
                    2
                }
            } else if raw.legacy_scrap_heap_only.unwrap_or(false) {
                1
            } else {
                default.allocator
            }
        });

        Self {
            allocator,
            gheap_task_safety: raw
                .gheap_task_safety
                .or(raw.legacy_gheap_task_release_guard)
                .unwrap_or(default.gheap_task_safety),
            gheap_periodic_pdd_purge: raw
                .gheap_periodic_pdd_purge
                .or(raw.legacy_gheap_periodic_full_pdd)
                .unwrap_or(default.gheap_periodic_pdd_purge),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PerformanceConfig {
    /// Replace the game's Mersenne Twister RNG.
    pub rng: bool,
    /// Replace zlib decompression.
    pub zlib: bool,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            rng: true,
            zlib: true,
        }
    }
}

impl PerformanceConfig {
    fn from_raw(
        raw: Option<RawPerformanceConfig>,
        legacy_perf: Option<RawPerfConfig>,
        legacy_zlib: Option<RawZlibConfig>,
    ) -> Self {
        let raw = raw.unwrap_or_default();
        let legacy_perf = legacy_perf.unwrap_or_default();
        let legacy_zlib = legacy_zlib.unwrap_or_default();
        let default = Self::default();

        Self {
            rng: raw.rng.or(legacy_perf.rng).unwrap_or(default.rng),
            zlib: raw.zlib.or(legacy_zlib.enabled).unwrap_or(default.zlib),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct EngineFixesConfig {
    /// Prevent the game from losing or blacking out the fullscreen window
    /// after alt-tab/focus changes.
    pub display_alt_tab: bool,
    /// Treat invalid NavMeshInfo low pointers as "no path identity".
    pub navmesh_low_pointer_guard: bool,
    /// Drop invalid ExtraContainerChanges::EntryData forms during load/save.
    pub entrydata_invalid_form_guard: bool,
    /// Scrub invalid ExtraOwnership.owner pointers to NULL.
    pub extraownership_invalid_owner_guard: bool,
    /// Compact NULL hkpEntity slots before hkpWorld::addEntityBatch.
    pub havok_add_entity_batch_null_guard: bool,
    /// Compact NULL hkpWorld pending-add slots before flush loops use them.
    pub havok_pending_add_null_guard: bool,
    /// Skip invalid Havok narrowphase collision pairs.
    pub havok_narrowphase_invalid_pair_guard: bool,
    /// Skip AddedToWorld callback dispatch for NULL hkpEntity pointers.
    pub havok_post_add_null_entity_guard: bool,
    /// Make the game's inlined memset a no-op for NULL destinations.
    pub memset_null_dst_guard: bool,
}

impl Default for EngineFixesConfig {
    fn default() -> Self {
        Self {
            display_alt_tab: true,
            navmesh_low_pointer_guard: true,
            entrydata_invalid_form_guard: true,
            extraownership_invalid_owner_guard: true,
            havok_add_entity_batch_null_guard: true,
            havok_pending_add_null_guard: true,
            havok_narrowphase_invalid_pair_guard: true,
            havok_post_add_null_entity_guard: true,
            memset_null_dst_guard: true,
        }
    }
}

impl EngineFixesConfig {
    fn from_raw(
        raw: Option<RawEngineFixesConfig>,
        legacy_display_tweaks: Option<bool>,
        legacy_display: Option<RawDisplayConfig>,
    ) -> Self {
        let raw = raw.unwrap_or_default();
        let legacy_display = legacy_display.unwrap_or_default();
        let default = Self::default();

        Self {
            display_alt_tab: raw
                .display_alt_tab
                .or(legacy_display_tweaks)
                .or(legacy_display.tweaks)
                .unwrap_or(default.display_alt_tab),
            navmesh_low_pointer_guard: raw
                .navmesh_low_pointer_guard
                .unwrap_or(default.navmesh_low_pointer_guard),
            entrydata_invalid_form_guard: raw
                .entrydata_invalid_form_guard
                .unwrap_or(default.entrydata_invalid_form_guard),
            extraownership_invalid_owner_guard: raw
                .extraownership_invalid_owner_guard
                .unwrap_or(default.extraownership_invalid_owner_guard),
            havok_add_entity_batch_null_guard: raw
                .havok_add_entity_batch_null_guard
                .unwrap_or(default.havok_add_entity_batch_null_guard),
            havok_pending_add_null_guard: raw
                .havok_pending_add_null_guard
                .unwrap_or(default.havok_pending_add_null_guard),
            havok_narrowphase_invalid_pair_guard: raw
                .havok_narrowphase_invalid_pair_guard
                .unwrap_or(default.havok_narrowphase_invalid_pair_guard),
            havok_post_add_null_entity_guard: raw
                .havok_post_add_null_entity_guard
                .unwrap_or(default.havok_post_add_null_entity_guard),
            memset_null_dst_guard: raw
                .memset_null_dst_guard
                .unwrap_or(default.memset_null_dst_guard),
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct DiagnosticsConfig {
    /// Open a Windows console window for real-time log output.
    pub console: bool,
    /// Use verbose log output.
    pub debug_log: bool,
}

impl DiagnosticsConfig {
    fn from_raw(
        raw: Option<RawDiagnosticsConfig>,
        legacy_general: Option<RawGeneralConfig>,
        legacy_logger: Option<RawLoggerConfig>,
    ) -> Self {
        let raw = raw.unwrap_or_default();
        let legacy_general = legacy_general.unwrap_or_default();
        let legacy_logger = legacy_logger.unwrap_or_default();

        Self {
            console: raw.console.or(legacy_general.console).unwrap_or_default(),
            debug_log: raw.debug_log.or(legacy_logger.debug).unwrap_or_default(),
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawPsychoConfig {
    memory: RawMemoryConfig,
    engine_fixes: Option<RawEngineFixesConfig>,
    performance: Option<RawPerformanceConfig>,
    diagnostics: Option<RawDiagnosticsConfig>,

    general: Option<RawGeneralConfig>,
    logger: Option<RawLoggerConfig>,
    perf: Option<RawPerfConfig>,
    zlib: Option<RawZlibConfig>,
    display: Option<RawDisplayConfig>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawMemoryConfig {
    allocator: Option<u8>,
    gheap_task_safety: Option<bool>,
    gheap_periodic_pdd_purge: Option<bool>,

    #[serde(rename = "heap_replacer")]
    legacy_heap_replacer: Option<bool>,
    #[serde(rename = "light_mode")]
    legacy_scrap_heap_only: Option<bool>,
    #[serde(rename = "gheap_task_release_guard")]
    legacy_gheap_task_release_guard: Option<bool>,
    #[serde(rename = "gheap_periodic_full_pdd")]
    legacy_gheap_periodic_full_pdd: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawPerformanceConfig {
    rng: Option<bool>,
    zlib: Option<bool>,
    /// Legacy key. New configs use engine_fixes.display_alt_tab.
    display_tweaks: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawEngineFixesConfig {
    display_alt_tab: Option<bool>,
    navmesh_low_pointer_guard: Option<bool>,
    entrydata_invalid_form_guard: Option<bool>,
    extraownership_invalid_owner_guard: Option<bool>,
    havok_add_entity_batch_null_guard: Option<bool>,
    havok_pending_add_null_guard: Option<bool>,
    havok_narrowphase_invalid_pair_guard: Option<bool>,
    havok_post_add_null_entity_guard: Option<bool>,
    memset_null_dst_guard: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawDiagnosticsConfig {
    console: Option<bool>,
    debug_log: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawGeneralConfig {
    console: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawLoggerConfig {
    debug: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawPerfConfig {
    rng: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawZlibConfig {
    enabled: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawDisplayConfig {
    tweaks: Option<bool>,
}

/// Load the global configuration (read-only, no file write-back).
///
/// Only does a single file read + TOML parse. Missing fields use defaults,
/// and old config keys are accepted for compatibility.
pub fn load_config() -> &'static PsychoConfig {
    CONFIG.get_or_init(|| {
        let path = config_path();

        let cfg = Config::load_readonly::<PsychoConfig>(path);
        log::info!("[CONFIG] Loaded '{}' (read-only)", path);
        cfg
    })
}

fn config_path() -> &'static str {
    if Path::new(CONFIG_PATH).exists() {
        return CONFIG_PATH;
    }

    LEGACY_CONFIG_PATHS
        .iter()
        .copied()
        .find(|path| Path::new(path).exists())
        .unwrap_or(CONFIG_PATH)
}

/// Get the global config reference.
pub fn get_config() -> anyhow::Result<&'static PsychoConfig> {
    CONFIG
        .get()
        .ok_or_else(|| anyhow::anyhow!("Config not loaded - call load_config() first"))
}

//! psycho configuration
//!
//! TOML-based runtime configuration.

use std::{path::Path, sync::OnceLock};

use serde::{Deserialize, Deserializer, Serialize};

use libpsycho::config::Config;

const CONFIG_PATH: &str = "syringe/psycho_engine_fixes.toml";
const LEGACY_CONFIG_PATHS: &[&str] = &[
    "mods/psycho_engine_fixes.toml",
    "mods/psycho.toml",
    "Data/NVSE/Plugins/psycho.toml",
    "Data/NVSE/Plugins/psycho-nvse.toml",
];

static CONFIG: OnceLock<PsychoConfig> = OnceLock::new();

#[derive(Debug, Default, Serialize)]
pub struct PsychoConfig {
    pub memory: MemoryConfig,
    pub engine_fixes: EngineFixesConfig,
    pub io: IoConfig,
    pub lod: LodConfig,
    pub performance: PerformanceConfig,
    pub diagnostics: DiagnosticsConfig,
}

impl<'de> Deserialize<'de> for PsychoConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawPsychoConfig::deserialize(deserializer)?;
        let legacy_display_tweaks = raw.performance.as_ref().and_then(|p| p.display_tweaks);
        let legacy_task_safety = raw
            .memory
            .gheap_task_safety
            .or(raw.memory.legacy_gheap_task_release_guard);
        Ok(Self {
            memory: MemoryConfig::from_raw(raw.memory),
            engine_fixes: EngineFixesConfig::from_raw(
                raw.engine_fixes,
                legacy_display_tweaks,
                raw.display,
                legacy_task_safety,
            ),
            io: IoConfig::from_raw(raw.io),
            lod: LodConfig::from_raw(raw.lod),
            performance: PerformanceConfig::from_raw(raw.performance, raw.perf, raw.zlib),
            diagnostics: DiagnosticsConfig::from_raw(raw.diagnostics, raw.general, raw.logger),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct MemoryConfig {
    /// 0 = vanilla heap, 1 = scrap_heap, 2 = gheap + scrap_heap.
    pub allocator: u8,
    /// Optional legacy full PDD purge. Keep off unless testing.
    pub gheap_periodic_pdd_purge: bool,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            allocator: 2,
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
            gheap_periodic_pdd_purge: raw
                .gheap_periodic_pdd_purge
                .or(raw.legacy_gheap_periodic_full_pdd)
                .unwrap_or(default.gheap_periodic_pdd_purge),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct IoConfig {
    /// Use exactly two native IOManager workers with audited shared-state guards.
    pub parallel_enabled: bool,
}

impl Default for IoConfig {
    fn default() -> Self {
        Self {
            parallel_enabled: true,
        }
    }
}

impl IoConfig {
    fn from_raw(raw: Option<RawIoConfig>) -> Self {
        let raw = raw.unwrap_or_default();
        let default = Self::default();
        Self {
            parallel_enabled: raw.parallel_enabled.unwrap_or(default.parallel_enabled),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct LodConfig {
    /// Enable the complete LOD engine improvement.
    pub enabled: bool,
    /// Request native LOD blocks before vanilla demand.
    pub prefetch_enabled: bool,
    /// Replace lifetime-total distant handoff readiness.
    pub handoff_fix_enabled: bool,
    /// Raise native LOD task priority without changing task classes.
    pub priority_boost_enabled: bool,
    pub object_prefetch_multiplier: f32,
    pub object_retention_multiplier: f32,
    pub tree_prefetch_multiplier: f32,
    pub tree_retention_multiplier: f32,
    pub terrain_prefetch_multiplier: f32,
    pub terrain_retention_multiplier: f32,
    #[serde(skip)]
    pub validation_adjusted: bool,
}

impl Default for LodConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prefetch_enabled: true,
            handoff_fix_enabled: true,
            priority_boost_enabled: true,
            object_prefetch_multiplier: 1.35,
            object_retention_multiplier: 1.50,
            tree_prefetch_multiplier: 1.35,
            tree_retention_multiplier: 1.50,
            terrain_prefetch_multiplier: 1.10,
            terrain_retention_multiplier: 1.20,
            validation_adjusted: false,
        }
    }
}

impl LodConfig {
    fn from_raw(raw: Option<RawLodConfig>) -> Self {
        let raw = raw.unwrap_or_default();
        let default = Self::default();
        let mut adjusted = false;

        let object_prefetch_multiplier = validate_lod_multiplier(
            raw.object_prefetch_multiplier,
            default.object_prefetch_multiplier,
            &mut adjusted,
        );
        let object_retention_multiplier = validate_lod_retention(
            raw.object_retention_multiplier,
            default.object_retention_multiplier,
            object_prefetch_multiplier,
            &mut adjusted,
        );
        let tree_prefetch_multiplier = validate_lod_multiplier(
            raw.tree_prefetch_multiplier,
            default.tree_prefetch_multiplier,
            &mut adjusted,
        );
        let tree_retention_multiplier = validate_lod_retention(
            raw.tree_retention_multiplier,
            default.tree_retention_multiplier,
            tree_prefetch_multiplier,
            &mut adjusted,
        );
        let terrain_prefetch_multiplier = validate_lod_multiplier(
            raw.terrain_prefetch_multiplier,
            default.terrain_prefetch_multiplier,
            &mut adjusted,
        );
        let terrain_retention_multiplier = validate_lod_retention(
            raw.terrain_retention_multiplier,
            default.terrain_retention_multiplier,
            terrain_prefetch_multiplier,
            &mut adjusted,
        );

        Self {
            enabled: raw.enabled.unwrap_or(default.enabled),
            prefetch_enabled: raw.prefetch_enabled.unwrap_or(default.prefetch_enabled),
            handoff_fix_enabled: raw
                .handoff_fix_enabled
                .unwrap_or(default.handoff_fix_enabled),
            priority_boost_enabled: raw
                .priority_boost_enabled
                .unwrap_or(default.priority_boost_enabled),
            object_prefetch_multiplier,
            object_retention_multiplier,
            tree_prefetch_multiplier,
            tree_retention_multiplier,
            terrain_prefetch_multiplier,
            terrain_retention_multiplier,
            validation_adjusted: adjusted,
        }
    }
}

fn validate_lod_multiplier(value: Option<f32>, default: f32, adjusted: &mut bool) -> f32 {
    let Some(value) = value else {
        return default;
    };
    if !value.is_finite() {
        *adjusted = true;
        return default;
    }
    let clamped = value.clamp(1.0, 2.0);
    *adjusted |= clamped != value;
    clamped
}

fn validate_lod_retention(
    value: Option<f32>,
    default: f32,
    prefetch: f32,
    adjusted: &mut bool,
) -> f32 {
    let retention = validate_lod_multiplier(value, default, adjusted);
    if retention < prefetch {
        *adjusted = true;
        prefetch
    } else {
        retention
    }
}

#[derive(Debug, Serialize)]
pub struct PerformanceConfig {
    /// Replace the game's Mersenne Twister RNG.
    pub rng: bool,
    /// Replace zlib decompression.
    pub zlib: bool,
    /// Drain post-load process reconciliation before returning from a successful load.
    pub post_load_reconciliation_prepass: bool,
    /// Existing configs may still contain removed radio optimization settings.
    #[serde(skip)]
    pub obsolete_radio_configured: bool,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            rng: true,
            zlib: true,
            post_load_reconciliation_prepass: true,
            obsolete_radio_configured: false,
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
            post_load_reconciliation_prepass: raw
                .post_load_reconciliation_prepass
                .unwrap_or(default.post_load_reconciliation_prepass),
            obsolete_radio_configured: raw.radio_pathfinder_yield_fix.is_some()
                || raw.radio_signal_scan_cache.is_some()
                || raw.radio_signal_scan_cache_ttl_ms.is_some(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct EngineFixesConfig {
    /// Repair audited fullscreen startup, reset, and Alt-Tab placement.
    pub display_alt_tab: bool,
    /// Commit saves durably and reject unsafe or unresolved changed records.
    pub save_integrity_fix: bool,
    /// Treat invalid NavMeshInfo low pointers as "no path identity".
    pub navmesh_low_pointer_guard: bool,
    /// Drop invalid ExtraContainerChanges::EntryData forms during load/save.
    pub entrydata_invalid_form_guard: bool,
    /// Scrub invalid ExtraOwnership.owner pointers to NULL.
    pub extraownership_invalid_owner_guard: bool,
    /// Ignore stale linked-reference child lists during save-to-save cleanup.
    pub linked_ref_children_stale_list_guard: bool,
    /// Treat linked-reference targets with invalid base forms as not matching the type gate.
    pub linked_ref_target_base_form_guard: bool,
    /// Skip ragdoll update frames while the Havok bone pointer table is not ready.
    pub ragdoll_null_bone_guard: bool,
    /// Treat penetration raycasts against detached Havok phantoms as no hit.
    pub ragdoll_detached_phantom_guard: bool,
    /// Compact NULL hkpEntity slots before hkpWorld::addEntityBatch.
    pub havok_add_entity_batch_null_guard: bool,
    /// Compact NULL hkpWorld pending-add slots before flush loops use them.
    pub havok_pending_add_null_guard: bool,
    /// Skip invalid Havok narrowphase collision pairs.
    pub havok_narrowphase_invalid_pair_guard: bool,
    /// Skip AddedToWorld callback dispatch for NULL hkpEntity pointers.
    pub havok_post_add_null_entity_guard: bool,
    /// Replace unsafe Havok remove-agent unlock dead-argument rereads.
    pub havok_remove_agent_null_reread_guard: bool,
    /// Guard the two allocator consumers that zero unchecked NULL results.
    pub memset_null_dst_guard: bool,
    /// Enforce LowProcess generic-location ownership and contain corrupt saves.
    pub lowprocess_generic_locations_fix: bool,
    /// Guard queued-task dispatch and release lifetime contracts.
    pub queued_task_lifetime_guard: bool,
}

impl Default for EngineFixesConfig {
    fn default() -> Self {
        Self {
            display_alt_tab: true,
            save_integrity_fix: true,
            navmesh_low_pointer_guard: true,
            entrydata_invalid_form_guard: true,
            extraownership_invalid_owner_guard: true,
            linked_ref_children_stale_list_guard: true,
            linked_ref_target_base_form_guard: true,
            ragdoll_null_bone_guard: true,
            ragdoll_detached_phantom_guard: true,
            havok_add_entity_batch_null_guard: true,
            havok_pending_add_null_guard: true,
            havok_narrowphase_invalid_pair_guard: true,
            havok_post_add_null_entity_guard: true,
            havok_remove_agent_null_reread_guard: true,
            memset_null_dst_guard: true,
            lowprocess_generic_locations_fix: true,
            queued_task_lifetime_guard: true,
        }
    }
}

impl EngineFixesConfig {
    fn from_raw(
        raw: Option<RawEngineFixesConfig>,
        legacy_display_tweaks: Option<bool>,
        legacy_display: Option<RawDisplayConfig>,
        legacy_task_safety: Option<bool>,
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
            save_integrity_fix: raw.save_integrity_fix.unwrap_or(default.save_integrity_fix),
            navmesh_low_pointer_guard: raw
                .navmesh_low_pointer_guard
                .unwrap_or(default.navmesh_low_pointer_guard),
            entrydata_invalid_form_guard: raw
                .entrydata_invalid_form_guard
                .unwrap_or(default.entrydata_invalid_form_guard),
            extraownership_invalid_owner_guard: raw
                .extraownership_invalid_owner_guard
                .unwrap_or(default.extraownership_invalid_owner_guard),
            linked_ref_children_stale_list_guard: raw
                .linked_ref_children_stale_list_guard
                .unwrap_or(default.linked_ref_children_stale_list_guard),
            linked_ref_target_base_form_guard: raw
                .linked_ref_target_base_form_guard
                .unwrap_or(default.linked_ref_target_base_form_guard),
            ragdoll_null_bone_guard: raw
                .ragdoll_null_bone_guard
                .unwrap_or(default.ragdoll_null_bone_guard),
            ragdoll_detached_phantom_guard: raw
                .ragdoll_detached_phantom_guard
                .unwrap_or(default.ragdoll_detached_phantom_guard),
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
            havok_remove_agent_null_reread_guard: raw
                .havok_remove_agent_null_reread_guard
                .unwrap_or(default.havok_remove_agent_null_reread_guard),
            memset_null_dst_guard: raw
                .memset_null_dst_guard
                .unwrap_or(default.memset_null_dst_guard),
            lowprocess_generic_locations_fix: raw
                .lowprocess_generic_locations_fix
                .unwrap_or(default.lowprocess_generic_locations_fix),
            queued_task_lifetime_guard: raw
                .queued_task_lifetime_guard
                .or(legacy_task_safety)
                .unwrap_or(default.queued_task_lifetime_guard),
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct DiagnosticsConfig {
    /// Open a Windows console window for real-time log output.
    pub console: bool,
    /// Use verbose log output.
    pub debug_log: bool,
    /// Time per-frame engine spans with QPC. Keep disabled outside focused profiling.
    pub hitch_profiling: bool,
    /// Record fixed-ring queued-task lifetime provenance.
    pub task_lifetime_trace: bool,
    /// Record fixed-ring LOD handoff transitions.
    pub lod_streaming_trace: bool,
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
            hitch_profiling: raw.hitch_profiling.unwrap_or_default(),
            task_lifetime_trace: raw.task_lifetime_trace.unwrap_or_default(),
            lod_streaming_trace: raw.lod_streaming_trace.unwrap_or_default(),
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawPsychoConfig {
    memory: RawMemoryConfig,
    engine_fixes: Option<RawEngineFixesConfig>,
    io: Option<RawIoConfig>,
    lod: Option<RawLodConfig>,
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
    radio_pathfinder_yield_fix: Option<bool>,
    post_load_reconciliation_prepass: Option<bool>,
    /// Removed keys retained only so startup can explain that they are ignored.
    radio_signal_scan_cache: Option<bool>,
    radio_signal_scan_cache_ttl_ms: Option<u32>,
    /// Legacy key. New configs use engine_fixes.display_alt_tab.
    display_tweaks: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawEngineFixesConfig {
    display_alt_tab: Option<bool>,
    save_integrity_fix: Option<bool>,
    navmesh_low_pointer_guard: Option<bool>,
    entrydata_invalid_form_guard: Option<bool>,
    extraownership_invalid_owner_guard: Option<bool>,
    linked_ref_children_stale_list_guard: Option<bool>,
    linked_ref_target_base_form_guard: Option<bool>,
    ragdoll_null_bone_guard: Option<bool>,
    ragdoll_detached_phantom_guard: Option<bool>,
    havok_add_entity_batch_null_guard: Option<bool>,
    havok_pending_add_null_guard: Option<bool>,
    havok_narrowphase_invalid_pair_guard: Option<bool>,
    havok_post_add_null_entity_guard: Option<bool>,
    havok_remove_agent_null_reread_guard: Option<bool>,
    memset_null_dst_guard: Option<bool>,
    lowprocess_generic_locations_fix: Option<bool>,
    queued_task_lifetime_guard: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawIoConfig {
    parallel_enabled: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawLodConfig {
    enabled: Option<bool>,
    prefetch_enabled: Option<bool>,
    handoff_fix_enabled: Option<bool>,
    priority_boost_enabled: Option<bool>,
    object_prefetch_multiplier: Option<f32>,
    object_retention_multiplier: Option<f32>,
    tree_prefetch_multiplier: Option<f32>,
    tree_retention_multiplier: Option<f32>,
    terrain_prefetch_multiplier: Option<f32>,
    terrain_retention_multiplier: Option<f32>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawDiagnosticsConfig {
    console: Option<bool>,
    debug_log: Option<bool>,
    hitch_profiling: Option<bool>,
    task_lifetime_trace: Option<bool>,
    lod_streaming_trace: Option<bool>,
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

#[cfg(test)]
mod tests {
    use super::PsychoConfig;

    #[test]
    fn io_parallelism_is_owned_by_io_section() {
        let config: PsychoConfig = toml::from_str(
            r#"
[io]
parallel_enabled = false

[lod]
enabled = true
"#,
        )
        .expect("parse IO configuration");

        assert!(!config.io.parallel_enabled);
        assert!(config.lod.enabled);
    }

    #[test]
    fn io_parallelism_defaults_on_without_an_io_section() {
        let config: PsychoConfig = toml::from_str("").expect("parse default configuration");

        assert!(config.io.parallel_enabled);
    }
}

//! Restart-only configuration editing for the dashboard.
//!
//! The helper preserves the user's comments and unknown keys with `toml_edit`.
//! It never mutates the core's already-published runtime configuration.

use std::{
    ffi::CString,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use libpsycho::os::windows::winapi::move_file_replace_write_through;
use toml_edit::{DocumentMut, Item, TableLike, value};

pub(crate) const CONFIG_PATH: &str = "syringe/psycho_engine_fixes.toml";
const LEGACY_CONFIG_PATHS: &[&str] = &[
    "mods/psycho_engine_fixes.toml",
    "mods/psycho.toml",
    "Data/NVSE/Plugins/psycho.toml",
    "Data/NVSE/Plugins/psycho-nvse.toml",
];

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct EditableConfig {
    pub allocator: i32,
    pub gheap_periodic_pdd_purge: bool,
    /// Restart-only repair of the two Bethesda installation-path values.
    pub install_path_registry_repair: bool,
    /// Restart-only absolute or FalloutNV-relative Fallout 3 directory.
    pub fallout3_install_path: String,
    pub display_alt_tab: bool,
    /// Restart-only borderless style preference for `bFull Screen=0`.
    pub display_borderless_windowed: bool,
    /// Restart-only confinement to the active mode-appropriate game boundary.
    pub window_cursor_lock: bool,
    /// Restart-only Windows/Super, PrintScreen, and media-key passthrough.
    pub input_system_key_passthrough: bool,
    pub save_integrity_fix: bool,
    pub navmesh_low_pointer_guard: bool,
    pub entrydata_invalid_form_guard: bool,
    pub actor_container_retirement_guard: bool,
    /// Restart-only animation-sequence ID-tag retirement preference.
    pub animation_sequence_idtag_retirement_guard: bool,
    pub extraownership_invalid_owner_guard: bool,
    /// Restart-only invalid encounter-zone form containment preference.
    pub encounter_zone_invalid_form_guard: bool,
    /// Restart-only cell render-list retirement cleanup preference.
    pub cell_render_reference_retirement_fix: bool,
    pub linked_ref_children_stale_list_guard: bool,
    pub linked_ref_target_base_form_guard: bool,
    pub ragdoll_null_bone_guard: bool,
    pub ragdoll_detached_phantom_guard: bool,
    pub havok_add_entity_batch_null_guard: bool,
    pub havok_pending_add_null_guard: bool,
    pub havok_narrowphase_invalid_pair_guard: bool,
    pub havok_post_add_null_entity_guard: bool,
    pub havok_remove_agent_null_reread_guard: bool,
    pub memset_null_dst_guard: bool,
    pub lowprocess_generic_locations_fix: bool,
    /// Restart-only model EditorMarker transaction serialization preference.
    pub model_postprocess_serialization_fix: bool,
    pub queued_task_lifetime_guard: bool,
    /// Restart-only patrol-owner FormID containment preference.
    pub patrol_owner_form_id_guard: bool,
    pub parallel_io: bool,
    pub lod_enabled: bool,
    pub lod_prefetch_enabled: bool,
    pub lod_handoff_fix_enabled: bool,
    pub lod_priority_boost_enabled: bool,
    /// Restart-only ordinary attachment budgeting preference.
    pub lod_attachment_budget_enabled: bool,
    pub object_prefetch_multiplier: f32,
    pub object_retention_multiplier: f32,
    pub tree_prefetch_multiplier: f32,
    pub tree_retention_multiplier: f32,
    pub terrain_prefetch_multiplier: f32,
    pub terrain_retention_multiplier: f32,
    pub rng: bool,
    pub zlib: bool,
    pub post_load_reconciliation_prepass: bool,
    /// Restart-only invocation-local native light-score reuse preference.
    pub light_property_score_reuse: bool,
    /// Restart-only sequential scene-light enumeration preference.
    pub scene_light_sequential_scan: bool,
    /// Restart-only native AABB/frustum setup reduction preference.
    pub multibound_frustum_tests: bool,
    /// Restart-only native compound/portal setup reduction preference.
    pub multibound_vertex_setup: bool,
    /// Restart-only native compound visibility bookkeeping preference.
    pub multibound_loop_bookkeeping: bool,
    /// Restart-only room/shared-root admission preference.
    pub scene_root_admission: bool,
    /// Restart-only native inverse-world expansion preference.
    pub inverse_world_index_setup: bool,
    /// Restart-only occlusion-plane injection preference.
    pub occlusion_planes: bool,
    /// Maximum injected planes per cell and shared neighbor budget.
    pub occlusion_planes_max_per_cell: i32,
    /// Loaded exterior-cell grid radius for cached occluder coverage.
    pub occlusion_planes_grid_radius: i32,
    /// Generated-plane cache file, relative to the game directory or absolute.
    pub occlusion_planes_cache_path: String,
    /// Verbose per-cell occlusion-plane diagnostics at debug level.
    pub occlusion_planes_debug_log: bool,
    pub debug_log: bool,
    pub console: bool,
    pub hitch_profiling: bool,
    pub task_lifetime_trace: bool,
    pub lod_streaming_trace: bool,
    /// Restart-only invalid source-texture dispatch containment.
    pub source_texture_cache_publication_guard: bool,
    /// Restart-only NULL Tile-value slot containment.
    pub tile_value_null_slot_guard: bool,
    /// Restart-only NULL model-cache string-key containment.
    pub model_cache_keys: bool,
    /// Restart-only unreadable linked-owner fading containment.
    pub fade_linked_owner_guard: bool,
    /// Restart-only unreadable native occlusion-plane containment.
    pub occlusion_link_guard: bool,
    /// Restart-only unreadable scene-owner base-form containment.
    pub scene_reference_owner_guard: bool,
    /// Restart-only invalid list-link and cycle cleanup containment.
    pub list_cleanup_guard: bool,
    /// Reject broken base-item lists before native inventory reset and refresh.
    pub inventory_reset_guard: bool,
}

impl Default for EditableConfig {
    fn default() -> Self {
        Self {
            allocator: 2,
            gheap_periodic_pdd_purge: false,
            install_path_registry_repair: true,
            fallout3_install_path: String::new(),
            display_alt_tab: true,
            display_borderless_windowed: true,
            window_cursor_lock: true,
            input_system_key_passthrough: true,
            save_integrity_fix: true,
            navmesh_low_pointer_guard: true,
            entrydata_invalid_form_guard: true,
            actor_container_retirement_guard: true,
            animation_sequence_idtag_retirement_guard: true,
            extraownership_invalid_owner_guard: true,
            encounter_zone_invalid_form_guard: true,
            cell_render_reference_retirement_fix: true,
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
            model_postprocess_serialization_fix: true,
            queued_task_lifetime_guard: true,
            patrol_owner_form_id_guard: true,
            parallel_io: true,
            lod_enabled: true,
            lod_prefetch_enabled: true,
            lod_handoff_fix_enabled: true,
            lod_priority_boost_enabled: true,
            lod_attachment_budget_enabled: true,
            object_prefetch_multiplier: 1.35,
            object_retention_multiplier: 1.50,
            tree_prefetch_multiplier: 1.35,
            tree_retention_multiplier: 1.50,
            terrain_prefetch_multiplier: 1.10,
            terrain_retention_multiplier: 1.20,
            rng: true,
            zlib: true,
            post_load_reconciliation_prepass: true,
            light_property_score_reuse: true,
            scene_light_sequential_scan: true,
            multibound_frustum_tests: true,
            multibound_vertex_setup: true,
            multibound_loop_bookkeeping: true,
            scene_root_admission: true,
            inverse_world_index_setup: true,
            occlusion_planes: true,
            occlusion_planes_max_per_cell: 128,
            occlusion_planes_grid_radius: 0,
            occlusion_planes_cache_path: "syringe/psycho_occlusion_planes.cache".to_owned(),
            occlusion_planes_debug_log: false,
            debug_log: false,
            console: false,
            hitch_profiling: false,
            task_lifetime_trace: false,
            lod_streaming_trace: false,
            source_texture_cache_publication_guard: true,
            tile_value_null_slot_guard: true,
            model_cache_keys: true,
            fade_linked_owner_guard: true,
            occlusion_link_guard: true,
            scene_reference_owner_guard: true,
            list_cleanup_guard: true,
            inventory_reset_guard: true,
        }
    }
}

impl EditableConfig {
    fn from_document(doc: &DocumentMut) -> Self {
        let defaults = Self::default();
        let legacy_heap = read_bool(doc, "memory", "heap_replacer");
        let legacy_light = read_bool(doc, "memory", "light_mode");
        let allocator = read_i64(doc, "memory", "allocator")
            .map(|value| value as i32)
            .unwrap_or_else(|| match (legacy_heap, legacy_light) {
                (Some(false), _) => 0,
                (_, Some(true)) => 1,
                _ => defaults.allocator,
            })
            .clamp(0, 2);

        Self {
            allocator,
            gheap_periodic_pdd_purge: read_bool(doc, "memory", "gheap_periodic_pdd_purge")
                .or_else(|| read_bool(doc, "memory", "gheap_periodic_full_pdd"))
                .unwrap_or(defaults.gheap_periodic_pdd_purge),
            install_path_registry_repair: bool_or(
                doc,
                "engine_fixes",
                "install_path_registry_repair",
                defaults.install_path_registry_repair,
            ),
            fallout3_install_path: read_string(doc, "engine_fixes", "fallout3_install_path")
                .unwrap_or(defaults.fallout3_install_path),
            display_alt_tab: read_bool(doc, "engine_fixes", "display_alt_tab")
                .or_else(|| read_bool(doc, "performance", "display_tweaks"))
                .or_else(|| read_bool(doc, "display", "tweaks"))
                .unwrap_or(defaults.display_alt_tab),
            display_borderless_windowed: bool_or(
                doc,
                "engine_fixes",
                "display_borderless_windowed",
                defaults.display_borderless_windowed,
            ),
            window_cursor_lock: bool_or(
                doc,
                "engine_fixes",
                "window_cursor_lock",
                defaults.window_cursor_lock,
            ),
            input_system_key_passthrough: bool_or(
                doc,
                "engine_fixes",
                "input_system_key_passthrough",
                defaults.input_system_key_passthrough,
            ),
            save_integrity_fix: bool_or(
                doc,
                "engine_fixes",
                "save_integrity_fix",
                defaults.save_integrity_fix,
            ),
            navmesh_low_pointer_guard: bool_or(
                doc,
                "engine_fixes",
                "navmesh_low_pointer_guard",
                defaults.navmesh_low_pointer_guard,
            ),
            entrydata_invalid_form_guard: bool_or(
                doc,
                "engine_fixes",
                "entrydata_invalid_form_guard",
                defaults.entrydata_invalid_form_guard,
            ),
            actor_container_retirement_guard: bool_or(
                doc,
                "engine_fixes",
                "actor_container_retirement_guard",
                defaults.actor_container_retirement_guard,
            ),
            animation_sequence_idtag_retirement_guard: bool_or(
                doc,
                "engine_fixes",
                "animation_sequence_idtag_retirement_guard",
                defaults.animation_sequence_idtag_retirement_guard,
            ),
            extraownership_invalid_owner_guard: bool_or(
                doc,
                "engine_fixes",
                "extraownership_invalid_owner_guard",
                defaults.extraownership_invalid_owner_guard,
            ),
            encounter_zone_invalid_form_guard: bool_or(
                doc,
                "engine_fixes",
                "encounter_zone_invalid_form_guard",
                defaults.encounter_zone_invalid_form_guard,
            ),
            cell_render_reference_retirement_fix: bool_or(
                doc,
                "engine_fixes",
                "cell_render_reference_retirement_fix",
                defaults.cell_render_reference_retirement_fix,
            ),
            linked_ref_children_stale_list_guard: bool_or(
                doc,
                "engine_fixes",
                "linked_ref_children_stale_list_guard",
                defaults.linked_ref_children_stale_list_guard,
            ),
            linked_ref_target_base_form_guard: bool_or(
                doc,
                "engine_fixes",
                "linked_ref_target_base_form_guard",
                defaults.linked_ref_target_base_form_guard,
            ),
            ragdoll_null_bone_guard: bool_or(
                doc,
                "engine_fixes",
                "ragdoll_null_bone_guard",
                defaults.ragdoll_null_bone_guard,
            ),
            ragdoll_detached_phantom_guard: bool_or(
                doc,
                "engine_fixes",
                "ragdoll_detached_phantom_guard",
                defaults.ragdoll_detached_phantom_guard,
            ),
            havok_add_entity_batch_null_guard: bool_or(
                doc,
                "engine_fixes",
                "havok_add_entity_batch_null_guard",
                defaults.havok_add_entity_batch_null_guard,
            ),
            havok_pending_add_null_guard: bool_or(
                doc,
                "engine_fixes",
                "havok_pending_add_null_guard",
                defaults.havok_pending_add_null_guard,
            ),
            havok_narrowphase_invalid_pair_guard: bool_or(
                doc,
                "engine_fixes",
                "havok_narrowphase_invalid_pair_guard",
                defaults.havok_narrowphase_invalid_pair_guard,
            ),
            havok_post_add_null_entity_guard: bool_or(
                doc,
                "engine_fixes",
                "havok_post_add_null_entity_guard",
                defaults.havok_post_add_null_entity_guard,
            ),
            havok_remove_agent_null_reread_guard: bool_or(
                doc,
                "engine_fixes",
                "havok_remove_agent_null_reread_guard",
                defaults.havok_remove_agent_null_reread_guard,
            ),
            memset_null_dst_guard: bool_or(
                doc,
                "engine_fixes",
                "memset_null_dst_guard",
                defaults.memset_null_dst_guard,
            ),
            lowprocess_generic_locations_fix: bool_or(
                doc,
                "engine_fixes",
                "lowprocess_generic_locations_fix",
                defaults.lowprocess_generic_locations_fix,
            ),
            model_postprocess_serialization_fix: bool_or(
                doc,
                "engine_fixes",
                "model_postprocess_serialization_fix",
                defaults.model_postprocess_serialization_fix,
            ),
            queued_task_lifetime_guard: read_bool(
                doc,
                "engine_fixes",
                "queued_task_lifetime_guard",
            )
            .or_else(|| read_bool(doc, "memory", "gheap_task_safety"))
            .or_else(|| read_bool(doc, "memory", "gheap_task_release_guard"))
            .unwrap_or(defaults.queued_task_lifetime_guard),
            patrol_owner_form_id_guard: bool_or(
                doc,
                "engine_fixes",
                "patrol_owner_form_id_guard",
                defaults.patrol_owner_form_id_guard,
            ),
            parallel_io: bool_or(doc, "io", "parallel_enabled", defaults.parallel_io),
            lod_enabled: bool_or(doc, "lod", "enabled", defaults.lod_enabled),
            lod_prefetch_enabled: bool_or(
                doc,
                "lod",
                "prefetch_enabled",
                defaults.lod_prefetch_enabled,
            ),
            lod_handoff_fix_enabled: bool_or(
                doc,
                "lod",
                "handoff_fix_enabled",
                defaults.lod_handoff_fix_enabled,
            ),
            lod_priority_boost_enabled: bool_or(
                doc,
                "lod",
                "priority_boost_enabled",
                defaults.lod_priority_boost_enabled,
            ),
            lod_attachment_budget_enabled: bool_or(
                doc,
                "lod",
                "attachment_budget_enabled",
                defaults.lod_attachment_budget_enabled,
            ),
            object_prefetch_multiplier: float_or(
                doc,
                "lod",
                "object_prefetch_multiplier",
                defaults.object_prefetch_multiplier,
            ),
            object_retention_multiplier: float_or(
                doc,
                "lod",
                "object_retention_multiplier",
                defaults.object_retention_multiplier,
            ),
            tree_prefetch_multiplier: float_or(
                doc,
                "lod",
                "tree_prefetch_multiplier",
                defaults.tree_prefetch_multiplier,
            ),
            tree_retention_multiplier: float_or(
                doc,
                "lod",
                "tree_retention_multiplier",
                defaults.tree_retention_multiplier,
            ),
            terrain_prefetch_multiplier: float_or(
                doc,
                "lod",
                "terrain_prefetch_multiplier",
                defaults.terrain_prefetch_multiplier,
            ),
            terrain_retention_multiplier: float_or(
                doc,
                "lod",
                "terrain_retention_multiplier",
                defaults.terrain_retention_multiplier,
            ),
            rng: read_bool(doc, "performance", "rng")
                .or_else(|| read_bool(doc, "perf", "rng"))
                .unwrap_or(defaults.rng),
            zlib: read_bool(doc, "performance", "zlib")
                .or_else(|| read_bool(doc, "zlib", "enabled"))
                .unwrap_or(defaults.zlib),
            post_load_reconciliation_prepass: bool_or(
                doc,
                "performance",
                "post_load_reconciliation_prepass",
                defaults.post_load_reconciliation_prepass,
            ),
            light_property_score_reuse: bool_or(
                doc,
                "performance",
                "light_property_score_reuse",
                defaults.light_property_score_reuse,
            ),
            scene_light_sequential_scan: bool_or(
                doc,
                "performance",
                "scene_light_sequential_scan",
                defaults.scene_light_sequential_scan,
            ),
            multibound_frustum_tests: bool_or(
                doc,
                "performance",
                "multibound_frustum_tests",
                defaults.multibound_frustum_tests,
            ),
            multibound_vertex_setup: bool_or(
                doc,
                "performance",
                "multibound_vertex_setup",
                defaults.multibound_vertex_setup,
            ),
            multibound_loop_bookkeeping: bool_or(
                doc,
                "performance",
                "multibound_loop_bookkeeping",
                defaults.multibound_loop_bookkeeping,
            ),
            scene_root_admission: bool_or(
                doc,
                "performance",
                "scene_root_admission",
                defaults.scene_root_admission,
            ),
            inverse_world_index_setup: bool_or(
                doc,
                "performance",
                "inverse_world_index_setup",
                defaults.inverse_world_index_setup,
            ),
            occlusion_planes: bool_or(
                doc,
                "performance",
                "occlusion_planes",
                defaults.occlusion_planes,
            ),
            occlusion_planes_max_per_cell: read_i64(
                doc,
                "performance",
                "occlusion_planes_max_per_cell",
            )
            .map(|value| value.clamp(1, 256) as i32)
            .unwrap_or(defaults.occlusion_planes_max_per_cell),
            occlusion_planes_grid_radius: read_i64(
                doc,
                "performance",
                "occlusion_planes_grid_radius",
            )
            .map(|value| value.clamp(0, 2) as i32)
            .unwrap_or(defaults.occlusion_planes_grid_radius),
            occlusion_planes_cache_path: read_string(
                doc,
                "performance",
                "occlusion_planes_cache_path",
            )
            .unwrap_or(defaults.occlusion_planes_cache_path),
            occlusion_planes_debug_log: bool_or(
                doc,
                "performance",
                "occlusion_planes_debug_log",
                defaults.occlusion_planes_debug_log,
            ),
            debug_log: read_bool(doc, "diagnostics", "debug_log")
                .or_else(|| read_bool(doc, "logger", "debug"))
                .unwrap_or(defaults.debug_log),
            console: read_bool(doc, "diagnostics", "console")
                .or_else(|| read_bool(doc, "general", "console"))
                .unwrap_or(defaults.console),
            hitch_profiling: bool_or(
                doc,
                "diagnostics",
                "hitch_profiling",
                defaults.hitch_profiling,
            ),
            task_lifetime_trace: bool_or(
                doc,
                "diagnostics",
                "task_lifetime_trace",
                defaults.task_lifetime_trace,
            ),
            lod_streaming_trace: bool_or(
                doc,
                "diagnostics",
                "lod_streaming_trace",
                defaults.lod_streaming_trace,
            ),
            source_texture_cache_publication_guard: bool_or(
                doc,
                "engine_fixes",
                "source_texture_cache_publication_guard",
                defaults.source_texture_cache_publication_guard,
            ),
            tile_value_null_slot_guard: bool_or(
                doc,
                "engine_fixes",
                "tile_value_null_slot_guard",
                defaults.tile_value_null_slot_guard,
            ),
            model_cache_keys: bool_or(
                doc,
                "engine_fixes",
                "model_cache_keys",
                defaults.model_cache_keys,
            ),
            fade_linked_owner_guard: bool_or(
                doc,
                "engine_fixes",
                "fade_linked_owner_guard",
                defaults.fade_linked_owner_guard,
            ),
            occlusion_link_guard: bool_or(
                doc,
                "engine_fixes",
                "occlusion_link_guard",
                defaults.occlusion_link_guard,
            ),
            scene_reference_owner_guard: bool_or(
                doc,
                "engine_fixes",
                "scene_reference_owner_guard",
                defaults.scene_reference_owner_guard,
            ),
            list_cleanup_guard: bool_or(
                doc,
                "engine_fixes",
                "list_cleanup_guard",
                defaults.list_cleanup_guard,
            ),
            inventory_reset_guard: bool_or(
                doc,
                "engine_fixes",
                "inventory_reset_guard",
                defaults.inventory_reset_guard,
            ),
        }
        .sanitized()
    }

    fn sanitized(mut self) -> Self {
        self.allocator = self.allocator.clamp(0, 2);
        self.occlusion_planes_max_per_cell = self.occlusion_planes_max_per_cell.clamp(1, 256);
        self.occlusion_planes_grid_radius = self.occlusion_planes_grid_radius.clamp(0, 2);
        self.object_prefetch_multiplier = finite_clamp(self.object_prefetch_multiplier, 1.35);
        self.object_retention_multiplier = finite_clamp(
            self.object_retention_multiplier,
            self.object_prefetch_multiplier,
        )
        .max(self.object_prefetch_multiplier);
        self.tree_prefetch_multiplier = finite_clamp(self.tree_prefetch_multiplier, 1.35);
        self.tree_retention_multiplier = finite_clamp(
            self.tree_retention_multiplier,
            self.tree_prefetch_multiplier,
        )
        .max(self.tree_prefetch_multiplier);
        self.terrain_prefetch_multiplier = finite_clamp(self.terrain_prefetch_multiplier, 1.10);
        self.terrain_retention_multiplier = finite_clamp(
            self.terrain_retention_multiplier,
            self.terrain_prefetch_multiplier,
        )
        .max(self.terrain_prefetch_multiplier);
        self
    }
}

pub(crate) struct ConfigEditor {
    pub path: PathBuf,
    pub draft: EditableConfig,
    saved: EditableConfig,
    original_content: String,
    document: Option<DocumentMut>,
    pub notice: Option<String>,
    pub error: Option<String>,
}

impl ConfigEditor {
    pub fn load() -> Self {
        Self::load_path(resolve_config_path())
    }

    fn load_path(path: PathBuf) -> Self {
        let content = match read_config_content(&path) {
            Ok(content) => content,
            Err(error) => {
                return Self {
                    path,
                    draft: EditableConfig::default(),
                    saved: EditableConfig::default(),
                    original_content: String::new(),
                    document: None,
                    notice: None,
                    error: Some(format!("Config read failed: {error:#}")),
                };
            }
        };
        match parse_document(&content) {
            Ok(document) => {
                let draft = EditableConfig::from_document(&document);
                Self {
                    path,
                    saved: draft.clone(),
                    draft,
                    original_content: content,
                    document: Some(document),
                    notice: None,
                    error: None,
                }
            }
            Err(error) => Self {
                path,
                draft: EditableConfig::default(),
                saved: EditableConfig::default(),
                original_content: content,
                document: None,
                notice: None,
                error: Some(format!("Config parse failed: {error:#}")),
            },
        }
    }

    pub fn is_dirty(&self) -> bool {
        self.draft != self.saved
    }

    pub fn reload(&mut self) {
        *self = Self::load_path(self.path.clone());
        if self.error.is_none() {
            self.notice = Some("Reloaded the restart configuration from disk.".to_owned());
        }
    }

    /// Revert the restart draft to the last loaded or saved file contents.
    ///
    /// Only the in-memory draft is dropped; the file is left untouched.
    pub fn discard(&mut self) {
        self.draft = self.saved.clone();
        self.error = None;
        self.notice = Some("Discarded unsaved changes.".to_owned());
    }

    pub fn save(&mut self) {
        match self.save_inner() {
            Ok(()) => {
                self.error = None;
                self.notice = Some(
                    "Saved. These settings become active after a full game restart.".to_owned(),
                );
            }
            Err(error) => {
                self.notice = None;
                self.error = Some(format!("Config save failed: {error:#}"));
            }
        }
    }

    fn save_inner(&mut self) -> Result<()> {
        let current = read_config_content(&self.path)?;
        if current != self.original_content {
            anyhow::bail!("the file changed outside the dashboard; reload before saving");
        }

        let mut document = self
            .document
            .as_ref()
            .context("the invalid TOML document cannot be overwritten")?
            .clone();
        self.draft = self.draft.clone().sanitized();
        write_document(&mut document, &self.draft);
        let updated = document.to_string();
        atomic_write(&self.path, updated.as_bytes())?;

        self.original_content = updated;
        self.document = Some(document);
        self.saved = self.draft.clone();
        Ok(())
    }
}

fn resolve_config_path() -> PathBuf {
    let primary = PathBuf::from(CONFIG_PATH);
    if primary.exists() {
        return primary;
    }
    LEGACY_CONFIG_PATHS
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
        .unwrap_or(primary)
}

fn parse_document(content: &str) -> Result<DocumentMut> {
    if content.trim().is_empty() {
        Ok(DocumentMut::new())
    } else {
        content.parse::<DocumentMut>().context("invalid TOML")
    }
}

fn read_config_content(path: &Path) -> Result<String> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(content),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

fn table<'a>(doc: &'a DocumentMut, section: &str) -> Option<&'a dyn TableLike> {
    doc.get(section)?.as_table_like()
}

fn item<'a>(doc: &'a DocumentMut, section: &str, key: &str) -> Option<&'a Item> {
    table(doc, section)?.get(key)
}

fn read_bool(doc: &DocumentMut, section: &str, key: &str) -> Option<bool> {
    item(doc, section, key)?.as_bool()
}

fn read_i64(doc: &DocumentMut, section: &str, key: &str) -> Option<i64> {
    item(doc, section, key)?.as_integer()
}

fn read_f64(doc: &DocumentMut, section: &str, key: &str) -> Option<f64> {
    let value = item(doc, section, key)?;
    value
        .as_float()
        .or_else(|| value.as_integer().map(|integer| integer as f64))
}

fn read_string(doc: &DocumentMut, section: &str, key: &str) -> Option<String> {
    item(doc, section, key)?.as_str().map(str::to_owned)
}

fn bool_or(doc: &DocumentMut, section: &str, key: &str, default: bool) -> bool {
    read_bool(doc, section, key).unwrap_or(default)
}

fn float_or(doc: &DocumentMut, section: &str, key: &str, default: f32) -> f32 {
    read_f64(doc, section, key)
        .map(|value| value as f32)
        .filter(|value| value.is_finite())
        .unwrap_or(default)
}

fn finite_clamp(value: f32, fallback: f32) -> f32 {
    if value.is_finite() {
        value.clamp(1.0, 2.0)
    } else {
        fallback
    }
}

fn write_document(doc: &mut DocumentMut, config: &EditableConfig) {
    set_document_value(
        doc,
        "memory",
        "allocator",
        value(i64::from(config.allocator)),
    );
    set_document_value(
        doc,
        "memory",
        "gheap_periodic_pdd_purge",
        value(config.gheap_periodic_pdd_purge),
    );

    macro_rules! engine {
        ($field:ident) => {
            set_document_value(
                doc,
                "engine_fixes",
                stringify!($field),
                value(config.$field),
            );
        };
    }
    engine!(display_alt_tab);
    engine!(install_path_registry_repair);
    set_document_value(
        doc,
        "engine_fixes",
        "fallout3_install_path",
        value(config.fallout3_install_path.clone()),
    );
    engine!(display_borderless_windowed);
    engine!(window_cursor_lock);
    engine!(input_system_key_passthrough);
    engine!(save_integrity_fix);
    engine!(navmesh_low_pointer_guard);
    engine!(entrydata_invalid_form_guard);
    engine!(actor_container_retirement_guard);
    engine!(animation_sequence_idtag_retirement_guard);
    engine!(extraownership_invalid_owner_guard);
    engine!(encounter_zone_invalid_form_guard);
    engine!(cell_render_reference_retirement_fix);
    engine!(linked_ref_children_stale_list_guard);
    engine!(linked_ref_target_base_form_guard);
    engine!(ragdoll_null_bone_guard);
    engine!(ragdoll_detached_phantom_guard);
    engine!(havok_add_entity_batch_null_guard);
    engine!(havok_pending_add_null_guard);
    engine!(havok_narrowphase_invalid_pair_guard);
    engine!(havok_post_add_null_entity_guard);
    engine!(havok_remove_agent_null_reread_guard);
    engine!(memset_null_dst_guard);
    engine!(lowprocess_generic_locations_fix);
    engine!(model_postprocess_serialization_fix);
    engine!(queued_task_lifetime_guard);
    engine!(patrol_owner_form_id_guard);
    engine!(source_texture_cache_publication_guard);
    engine!(tile_value_null_slot_guard);
    engine!(model_cache_keys);
    engine!(fade_linked_owner_guard);
    engine!(occlusion_link_guard);
    engine!(scene_reference_owner_guard);
    engine!(list_cleanup_guard);
    engine!(inventory_reset_guard);

    macro_rules! setting {
        ($section:literal, $key:literal, $field:ident) => {
            set_document_value(doc, $section, $key, value(config.$field));
        };
        ($section:literal, $key:literal, $field:ident as f64) => {
            set_document_value(doc, $section, $key, value(config.$field as f64));
        };
        ($section:literal, $key:literal, $field:ident as i64) => {
            set_document_value(doc, $section, $key, value(i64::from(config.$field)));
        };
    }

    setting!("io", "parallel_enabled", parallel_io);
    setting!("lod", "enabled", lod_enabled);
    setting!("lod", "prefetch_enabled", lod_prefetch_enabled);
    setting!("lod", "handoff_fix_enabled", lod_handoff_fix_enabled);
    setting!("lod", "priority_boost_enabled", lod_priority_boost_enabled);
    setting!(
        "lod",
        "attachment_budget_enabled",
        lod_attachment_budget_enabled
    );
    setting!(
        "lod",
        "object_prefetch_multiplier",
        object_prefetch_multiplier as f64
    );
    setting!(
        "lod",
        "object_retention_multiplier",
        object_retention_multiplier as f64
    );
    setting!(
        "lod",
        "tree_prefetch_multiplier",
        tree_prefetch_multiplier as f64
    );
    setting!(
        "lod",
        "tree_retention_multiplier",
        tree_retention_multiplier as f64
    );
    setting!(
        "lod",
        "terrain_prefetch_multiplier",
        terrain_prefetch_multiplier as f64
    );
    setting!(
        "lod",
        "terrain_retention_multiplier",
        terrain_retention_multiplier as f64
    );
    setting!("performance", "rng", rng);
    setting!("performance", "zlib", zlib);
    setting!(
        "performance",
        "post_load_reconciliation_prepass",
        post_load_reconciliation_prepass
    );
    setting!(
        "performance",
        "light_property_score_reuse",
        light_property_score_reuse
    );
    setting!(
        "performance",
        "scene_light_sequential_scan",
        scene_light_sequential_scan
    );
    setting!(
        "performance",
        "multibound_frustum_tests",
        multibound_frustum_tests
    );
    setting!(
        "performance",
        "multibound_vertex_setup",
        multibound_vertex_setup
    );
    setting!(
        "performance",
        "multibound_loop_bookkeeping",
        multibound_loop_bookkeeping
    );
    setting!("performance", "scene_root_admission", scene_root_admission);
    setting!(
        "performance",
        "inverse_world_index_setup",
        inverse_world_index_setup
    );
    setting!("performance", "occlusion_planes", occlusion_planes);
    setting!(
        "performance",
        "occlusion_planes_max_per_cell",
        occlusion_planes_max_per_cell as i64
    );
    setting!(
        "performance",
        "occlusion_planes_grid_radius",
        occlusion_planes_grid_radius as i64
    );
    set_document_value(
        doc,
        "performance",
        "occlusion_planes_cache_path",
        value(config.occlusion_planes_cache_path.clone()),
    );
    setting!(
        "performance",
        "occlusion_planes_debug_log",
        occlusion_planes_debug_log
    );
    setting!("diagnostics", "debug_log", debug_log);
    setting!("diagnostics", "console", console);
    setting!("diagnostics", "hitch_profiling", hitch_profiling);
    setting!("diagnostics", "task_lifetime_trace", task_lifetime_trace);
    setting!("diagnostics", "lod_streaming_trace", lod_streaming_trace);
}

fn set_document_value(doc: &mut DocumentMut, section: &str, key: &str, mut replacement: Item) {
    let decor = item(doc, section, key)
        .and_then(Item::as_value)
        .map(|value| value.decor().clone());
    if let (Some(decor), Some(value)) = (decor, replacement.as_value_mut()) {
        *value.decor_mut() = decor;
    }
    doc[section][key] = replacement;
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }

    let temp = path.with_extension("toml.dashboard.tmp");
    let mut file = File::create(&temp).with_context(|| format!("create {}", temp.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write {}", temp.display()))?;
    file.sync_all()
        .with_context(|| format!("flush {}", temp.display()))?;
    drop(file);

    let source = path_cstring(&temp)?;
    let destination = path_cstring(path)?;
    if let Err(error) = move_file_replace_write_through(&source, &destination) {
        let _ = fs::remove_file(&temp);
        return Err(error).with_context(|| format!("replace {}", path.display()));
    }
    Ok(())
}

fn path_cstring(path: &Path) -> Result<CString> {
    CString::new(path.to_string_lossy().as_bytes())
        .with_context(|| format!("path contains NUL: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::{ConfigEditor, EditableConfig, parse_document, write_document};
    use std::path::PathBuf;

    #[test]
    fn edited_document_preserves_comments_and_unknown_mod_keys() {
        let source = r#"# keep this support note
[memory]
allocator = 1 # keep this inline note
mod_owned_key = "untouched"
"#;
        let mut document = parse_document(source).expect("parse source");
        let mut config = EditableConfig::from_document(&document);
        config.allocator = 2;
        config.install_path_registry_repair = false;
        config.fallout3_install_path = r"..\Fallout 3".to_owned();
        config.display_borderless_windowed = false;
        config.window_cursor_lock = false;
        config.input_system_key_passthrough = false;
        config.actor_container_retirement_guard = false;
        config.animation_sequence_idtag_retirement_guard = false;
        config.encounter_zone_invalid_form_guard = false;
        config.cell_render_reference_retirement_fix = false;
        config.model_postprocess_serialization_fix = false;
        config.source_texture_cache_publication_guard = false;
        config.tile_value_null_slot_guard = false;
        config.lod_attachment_budget_enabled = false;
        config.light_property_score_reuse = false;
        config.scene_light_sequential_scan = false;
        config.multibound_frustum_tests = false;
        config.multibound_vertex_setup = false;
        config.multibound_loop_bookkeeping = false;
        config.scene_root_admission = false;
        config.inverse_world_index_setup = false;
        config.occlusion_planes = false;
        config.occlusion_planes_max_per_cell = 64;
        config.occlusion_planes_grid_radius = 2;
        config.occlusion_planes_cache_path = "cache/planes.cache".to_owned();
        write_document(&mut document, &config);
        let saved = document.to_string();

        assert!(saved.contains("# keep this support note"));
        assert!(saved.contains("# keep this inline note"));
        assert!(saved.contains("mod_owned_key = \"untouched\""));
        assert!(saved.contains("allocator = 2"));
        assert!(saved.contains("install_path_registry_repair = false"));
        assert!(saved.contains("fallout3_install_path"));
        assert!(saved.contains("display_borderless_windowed = false"));
        assert!(saved.contains("window_cursor_lock = false"));
        assert!(saved.contains("input_system_key_passthrough = false"));
        assert!(saved.contains("actor_container_retirement_guard = false"));
        assert!(saved.contains("animation_sequence_idtag_retirement_guard = false"));
        assert!(saved.contains("encounter_zone_invalid_form_guard = false"));
        assert!(saved.contains("cell_render_reference_retirement_fix = false"));
        assert!(saved.contains("model_postprocess_serialization_fix = false"));
        assert!(saved.contains("source_texture_cache_publication_guard = false"));
        assert!(saved.contains("tile_value_null_slot_guard = false"));
        assert!(saved.contains("light_property_score_reuse = false"));
        assert!(saved.contains("occlusion_planes_max_per_cell = 64"));
        assert!(saved.contains("occlusion_planes_grid_radius = 2"));
        assert!(saved.contains("cache/planes.cache"));
        let reparsed = parse_document(&saved).expect("parse saved document");
        assert!(!EditableConfig::from_document(&reparsed).install_path_registry_repair);
        assert_eq!(
            EditableConfig::from_document(&reparsed).fallout3_install_path,
            r"..\Fallout 3"
        );
        assert!(!EditableConfig::from_document(&reparsed).display_borderless_windowed);
        assert!(!EditableConfig::from_document(&reparsed).window_cursor_lock);
        assert!(!EditableConfig::from_document(&reparsed).input_system_key_passthrough);
        assert!(!EditableConfig::from_document(&reparsed).actor_container_retirement_guard);
        assert!(
            !EditableConfig::from_document(&reparsed).animation_sequence_idtag_retirement_guard
        );
        assert!(!EditableConfig::from_document(&reparsed).encounter_zone_invalid_form_guard);
        assert!(!EditableConfig::from_document(&reparsed).cell_render_reference_retirement_fix);
        assert!(!EditableConfig::from_document(&reparsed).model_postprocess_serialization_fix);
        assert!(!EditableConfig::from_document(&reparsed).source_texture_cache_publication_guard);
        assert!(!EditableConfig::from_document(&reparsed).tile_value_null_slot_guard);
        assert!(!EditableConfig::from_document(&reparsed).lod_attachment_budget_enabled);
        assert!(!EditableConfig::from_document(&reparsed).light_property_score_reuse);
        assert!(!EditableConfig::from_document(&reparsed).scene_light_sequential_scan);
        assert!(!EditableConfig::from_document(&reparsed).multibound_frustum_tests);
        assert!(!EditableConfig::from_document(&reparsed).multibound_vertex_setup);
        assert!(!EditableConfig::from_document(&reparsed).multibound_loop_bookkeeping);
        assert!(!EditableConfig::from_document(&reparsed).scene_root_admission);
        assert!(!EditableConfig::from_document(&reparsed).inverse_world_index_setup);
        assert!(!EditableConfig::from_document(&reparsed).occlusion_planes);
        assert_eq!(
            EditableConfig::from_document(&reparsed).occlusion_planes_max_per_cell,
            64
        );
        assert_eq!(
            EditableConfig::from_document(&reparsed).occlusion_planes_grid_radius,
            2
        );
        assert_eq!(
            EditableConfig::from_document(&reparsed).occlusion_planes_cache_path,
            "cache/planes.cache"
        );
    }

    #[test]
    fn shipped_configuration_round_trips_every_editable_field() {
        let source = include_str!("../../psycho-engine-fixes/config/psycho_engine_fixes.toml");
        let mut document = parse_document(source).expect("shipped configuration parses");
        let mut config = EditableConfig::from_document(&document);

        // Invert every boolean and move both bounded numbers away from their
        // defaults so the round trip proves each field is actually serialized.
        config.allocator = 1;
        config.gheap_periodic_pdd_purge = !config.gheap_periodic_pdd_purge;
        config.install_path_registry_repair = !config.install_path_registry_repair;
        config.fallout3_install_path = r"..\Fallout 3".to_owned();
        config.display_alt_tab = !config.display_alt_tab;
        config.display_borderless_windowed = !config.display_borderless_windowed;
        config.window_cursor_lock = !config.window_cursor_lock;
        config.input_system_key_passthrough = !config.input_system_key_passthrough;
        config.save_integrity_fix = !config.save_integrity_fix;
        config.navmesh_low_pointer_guard = !config.navmesh_low_pointer_guard;
        config.entrydata_invalid_form_guard = !config.entrydata_invalid_form_guard;
        config.actor_container_retirement_guard = !config.actor_container_retirement_guard;
        config.animation_sequence_idtag_retirement_guard =
            !config.animation_sequence_idtag_retirement_guard;
        config.extraownership_invalid_owner_guard = !config.extraownership_invalid_owner_guard;
        config.encounter_zone_invalid_form_guard = !config.encounter_zone_invalid_form_guard;
        config.cell_render_reference_retirement_fix = !config.cell_render_reference_retirement_fix;
        config.linked_ref_children_stale_list_guard = !config.linked_ref_children_stale_list_guard;
        config.linked_ref_target_base_form_guard = !config.linked_ref_target_base_form_guard;
        config.scene_reference_owner_guard = !config.scene_reference_owner_guard;
        config.list_cleanup_guard = !config.list_cleanup_guard;
        config.inventory_reset_guard = !config.inventory_reset_guard;
        config.ragdoll_null_bone_guard = !config.ragdoll_null_bone_guard;
        config.ragdoll_detached_phantom_guard = !config.ragdoll_detached_phantom_guard;
        config.havok_add_entity_batch_null_guard = !config.havok_add_entity_batch_null_guard;
        config.havok_pending_add_null_guard = !config.havok_pending_add_null_guard;
        config.havok_narrowphase_invalid_pair_guard = !config.havok_narrowphase_invalid_pair_guard;
        config.havok_post_add_null_entity_guard = !config.havok_post_add_null_entity_guard;
        config.havok_remove_agent_null_reread_guard = !config.havok_remove_agent_null_reread_guard;
        config.memset_null_dst_guard = !config.memset_null_dst_guard;
        config.lowprocess_generic_locations_fix = !config.lowprocess_generic_locations_fix;
        config.model_postprocess_serialization_fix = !config.model_postprocess_serialization_fix;
        config.queued_task_lifetime_guard = !config.queued_task_lifetime_guard;
        config.patrol_owner_form_id_guard = !config.patrol_owner_form_id_guard;
        config.source_texture_cache_publication_guard =
            !config.source_texture_cache_publication_guard;
        config.tile_value_null_slot_guard = !config.tile_value_null_slot_guard;
        config.parallel_io = !config.parallel_io;
        config.lod_enabled = !config.lod_enabled;
        config.lod_prefetch_enabled = !config.lod_prefetch_enabled;
        config.lod_handoff_fix_enabled = !config.lod_handoff_fix_enabled;
        config.lod_priority_boost_enabled = !config.lod_priority_boost_enabled;
        config.lod_attachment_budget_enabled = !config.lod_attachment_budget_enabled;
        config.object_prefetch_multiplier = 1.85;
        config.object_retention_multiplier = 1.95;
        config.tree_prefetch_multiplier = 1.75;
        config.tree_retention_multiplier = 1.80;
        config.terrain_prefetch_multiplier = 1.60;
        config.terrain_retention_multiplier = 1.70;
        config.rng = !config.rng;
        config.zlib = !config.zlib;
        config.post_load_reconciliation_prepass = !config.post_load_reconciliation_prepass;
        config.light_property_score_reuse = !config.light_property_score_reuse;
        config.scene_light_sequential_scan = !config.scene_light_sequential_scan;
        config.multibound_frustum_tests = !config.multibound_frustum_tests;
        config.multibound_vertex_setup = !config.multibound_vertex_setup;
        config.multibound_loop_bookkeeping = !config.multibound_loop_bookkeeping;
        config.scene_root_admission = !config.scene_root_admission;
        config.inverse_world_index_setup = !config.inverse_world_index_setup;
        config.occlusion_planes = !config.occlusion_planes;
        config.occlusion_planes_max_per_cell = 200;
        config.occlusion_planes_grid_radius = 1;
        config.occlusion_planes_cache_path = "cache/custom.cache".to_owned();
        config.occlusion_planes_debug_log = !config.occlusion_planes_debug_log;
        config.debug_log = !config.debug_log;
        config.console = !config.console;
        config.hitch_profiling = !config.hitch_profiling;
        config.task_lifetime_trace = !config.task_lifetime_trace;
        config.lod_streaming_trace = !config.lod_streaming_trace;

        write_document(&mut document, &config);
        let saved = document.to_string();
        let reparsed = parse_document(&saved).expect("saved shipped configuration parses");
        let actual = EditableConfig::from_document(&reparsed);

        assert_eq!(actual, config.sanitized());
    }

    #[test]
    fn dirty_state_tracks_restart_draft() {
        let document = parse_document("").expect("empty document");
        let config = EditableConfig::from_document(&document);
        let mut editor = ConfigEditor {
            path: PathBuf::from("unused.toml"),
            draft: config.clone(),
            saved: config,
            original_content: String::new(),
            document: Some(document),
            notice: None,
            error: None,
        };
        assert!(!editor.is_dirty());
        assert!(editor.draft.window_cursor_lock);
        assert!(editor.draft.input_system_key_passthrough);
        editor.draft.debug_log = !editor.draft.debug_log;
        assert!(editor.is_dirty());
    }

    #[test]
    fn legacy_values_match_the_core_fallback_order() {
        let document = parse_document(
            r#"
[memory]
heap_replacer = true
light_mode = true
gheap_periodic_full_pdd = true
gheap_task_release_guard = false

[lod]
object_prefetch_multiplier = 1
"#,
        )
        .expect("legacy document");
        let config = EditableConfig::from_document(&document);

        assert_eq!(config.allocator, 1);
        assert!(config.gheap_periodic_pdd_purge);
        assert!(!config.queued_task_lifetime_guard);
        assert!(config.actor_container_retirement_guard);
        assert!(config.encounter_zone_invalid_form_guard);
        assert!(config.cell_render_reference_retirement_fix);
        assert_eq!(config.object_prefetch_multiplier, 1.0);
        assert!(config.lod_attachment_budget_enabled);
        assert!(!config.debug_log);
    }
}

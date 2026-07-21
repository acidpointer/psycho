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

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct EditableConfig {
    pub allocator: i32,
    pub gheap_periodic_pdd_purge: bool,
    pub display_alt_tab: bool,
    pub save_integrity_fix: bool,
    pub navmesh_low_pointer_guard: bool,
    pub entrydata_invalid_form_guard: bool,
    pub extraownership_invalid_owner_guard: bool,
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
    pub queued_task_lifetime_guard: bool,
    pub parallel_io: bool,
    pub lod_enabled: bool,
    pub lod_prefetch_enabled: bool,
    pub lod_handoff_fix_enabled: bool,
    pub lod_priority_boost_enabled: bool,
    pub object_prefetch_multiplier: f32,
    pub object_retention_multiplier: f32,
    pub tree_prefetch_multiplier: f32,
    pub tree_retention_multiplier: f32,
    pub terrain_prefetch_multiplier: f32,
    pub terrain_retention_multiplier: f32,
    pub rng: bool,
    pub zlib: bool,
    pub post_load_reconciliation_prepass: bool,
    pub debug_log: bool,
    pub console: bool,
    pub hitch_profiling: bool,
    pub task_lifetime_trace: bool,
    pub lod_streaming_trace: bool,
}

impl Default for EditableConfig {
    fn default() -> Self {
        Self {
            allocator: 2,
            gheap_periodic_pdd_purge: false,
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
            parallel_io: true,
            lod_enabled: true,
            lod_prefetch_enabled: true,
            lod_handoff_fix_enabled: true,
            lod_priority_boost_enabled: true,
            object_prefetch_multiplier: 1.35,
            object_retention_multiplier: 1.50,
            tree_prefetch_multiplier: 1.35,
            tree_retention_multiplier: 1.50,
            terrain_prefetch_multiplier: 1.10,
            terrain_retention_multiplier: 1.20,
            rng: true,
            zlib: true,
            post_load_reconciliation_prepass: true,
            debug_log: false,
            console: false,
            hitch_profiling: false,
            task_lifetime_trace: false,
            lod_streaming_trace: false,
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
            display_alt_tab: read_bool(doc, "engine_fixes", "display_alt_tab")
                .or_else(|| read_bool(doc, "performance", "display_tweaks"))
                .or_else(|| read_bool(doc, "display", "tweaks"))
                .unwrap_or(defaults.display_alt_tab),
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
            extraownership_invalid_owner_guard: bool_or(
                doc,
                "engine_fixes",
                "extraownership_invalid_owner_guard",
                defaults.extraownership_invalid_owner_guard,
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
            queued_task_lifetime_guard: read_bool(
                doc,
                "engine_fixes",
                "queued_task_lifetime_guard",
            )
            .or_else(|| read_bool(doc, "memory", "gheap_task_safety"))
            .or_else(|| read_bool(doc, "memory", "gheap_task_release_guard"))
            .unwrap_or(defaults.queued_task_lifetime_guard),
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
        }
        .sanitized()
    }

    fn sanitized(mut self) -> Self {
        self.allocator = self.allocator.clamp(0, 2);
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
                    draft,
                    saved: draft,
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
        self.draft = self.draft.sanitized();
        write_document(&mut document, &self.draft);
        let updated = document.to_string();
        atomic_write(&self.path, updated.as_bytes())?;

        self.original_content = updated;
        self.document = Some(document);
        self.saved = self.draft;
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
    engine!(save_integrity_fix);
    engine!(navmesh_low_pointer_guard);
    engine!(entrydata_invalid_form_guard);
    engine!(extraownership_invalid_owner_guard);
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
    engine!(queued_task_lifetime_guard);

    macro_rules! setting {
        ($section:literal, $key:literal, $field:ident) => {
            set_document_value(doc, $section, $key, value(config.$field));
        };
        ($section:literal, $key:literal, $field:ident as f64) => {
            set_document_value(doc, $section, $key, value(config.$field as f64));
        };
    }

    setting!("io", "parallel_enabled", parallel_io);
    setting!("lod", "enabled", lod_enabled);
    setting!("lod", "prefetch_enabled", lod_prefetch_enabled);
    setting!("lod", "handoff_fix_enabled", lod_handoff_fix_enabled);
    setting!("lod", "priority_boost_enabled", lod_priority_boost_enabled);
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
        write_document(&mut document, &config);
        let saved = document.to_string();

        assert!(saved.contains("# keep this support note"));
        assert!(saved.contains("# keep this inline note"));
        assert!(saved.contains("mod_owned_key = \"untouched\""));
        assert!(saved.contains("allocator = 2"));
    }

    #[test]
    fn dirty_state_tracks_restart_draft() {
        let document = parse_document("").expect("empty document");
        let config = EditableConfig::from_document(&document);
        let mut editor = ConfigEditor {
            path: PathBuf::from("unused.toml"),
            draft: config,
            saved: config,
            original_content: String::new(),
            document: Some(document),
            notice: None,
            error: None,
        };
        assert!(!editor.is_dirty());
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
        assert_eq!(config.object_prefetch_multiplier, 1.0);
        assert!(!config.debug_log);
    }
}

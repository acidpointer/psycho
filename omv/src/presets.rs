//! Versioned, shareable graphics presets.
//!
//! `omv.toml` remains the working configuration. Presets are versioned visual
//! snapshots that are parsed and migrated before they can replace the visual
//! portion of that working configuration. Machine-bound controls, including
//! the depth provider, menu key, scan interval, and diagnostics, are
//! intentionally absent from `PresetVisualSettingsV1`; applying a shared
//! preset must never replace them. Explicit version publication atomically
//! updates one preset file; activation and Current Look autosaves never mutate
//! preset files.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel},
    thread,
};

use anyhow::{Context, Result, anyhow, bail};
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::{
    config::{
        EmbeddedEffectsConfig, GraphicsMenuConfig, NativePbrConfig, NativeSkyConfig,
        PsychoGraphicsConfig,
    },
    luts::LutCatalog,
    shaders::{
        ScreenShaderSource, ShaderOptionValue, ShaderPhase, merge_embedded_sources_with_luts,
    },
};

pub(crate) const PRESET_DIRECTORY: &str = "Data/NVSE/plugins/omv/presets";
const PRESET_STATE_PATH: &str = "Data/NVSE/plugins/omv/omv-state.toml";
const PRESET_SUFFIX: &str = ".omvpreset.toml";
const PRESET_MAGIC: &str = "omv-preset";
const PRESET_FORMAT_VERSION: u32 = 1;
const MAX_PRESET_BYTES: u64 = 1024 * 1024;
const MAX_PRESET_SCAN_DEPTH: usize = 4;
const MAX_PRESET_NAME_ATTEMPTS: u32 = 10_000;
const DEFAULT_PRESET_ID: &str = "00000000-0000-4000-8000-000000000001";
const DEFAULT_PRESET_VERSION: &str = "1.0.0";
#[cfg(test)]
const DEFAULT_PRESET_PAYLOAD_REVISION: u64 = 0x27f0_1c85_96dc_549c;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct PresetKey {
    pub(crate) id: String,
    pub(crate) version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PresetMetadata {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) author: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) description: String,
    pub(crate) created_with: PresetBuildProvenance,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PresetBuildProvenance {
    pub(crate) omv_version: String,
    pub(crate) git_commit: String,
    pub(crate) git_tag: String,
    pub(crate) git_branch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) git_dirty: Option<bool>,
}

impl PresetBuildProvenance {
    fn current() -> Self {
        Self {
            omv_version: env!("CARGO_PKG_VERSION").to_owned(),
            git_commit: option_env!("OMV_GIT_COMMIT")
                .unwrap_or("unknown")
                .to_owned(),
            git_tag: option_env!("OMV_GIT_TAG").unwrap_or("").to_owned(),
            git_branch: option_env!("OMV_GIT_BRANCH")
                .unwrap_or("unknown")
                .to_owned(),
            git_dirty: match option_env!("OMV_GIT_DIRTY") {
                Some("true") => Some(true),
                Some("false") => Some(false),
                _ => None,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PresetNativePbrV1 {
    enabled: bool,
    object_roughness_scale: f32,
    object_light_scale: f32,
    object_ambient_scale: f32,
    object_albedo_saturation: f32,
    terrain_metallicness: f32,
    terrain_roughness_scale: f32,
    terrain_light_scale: f32,
    terrain_ambient_scale: f32,
    terrain_albedo_saturation: f32,
    terrain_lod_noise_scale: f32,
    terrain_lod_noise_tile: f32,
}

impl From<NativePbrConfig> for PresetNativePbrV1 {
    fn from(value: NativePbrConfig) -> Self {
        Self {
            enabled: value.enabled,
            object_roughness_scale: value.object_roughness_scale,
            object_light_scale: value.object_light_scale,
            object_ambient_scale: value.object_ambient_scale,
            object_albedo_saturation: value.object_albedo_saturation,
            terrain_metallicness: value.terrain_metallicness,
            terrain_roughness_scale: value.terrain_roughness_scale,
            terrain_light_scale: value.terrain_light_scale,
            terrain_ambient_scale: value.terrain_ambient_scale,
            terrain_albedo_saturation: value.terrain_albedo_saturation,
            terrain_lod_noise_scale: value.terrain_lod_noise_scale,
            terrain_lod_noise_tile: value.terrain_lod_noise_tile,
        }
    }
}

impl PresetNativePbrV1 {
    fn apply(self, target: &mut NativePbrConfig) {
        let debug_log_draws = target.debug_log_draws;
        *target = NativePbrConfig {
            enabled: self.enabled,
            debug_log_draws,
            object_roughness_scale: self.object_roughness_scale,
            object_light_scale: self.object_light_scale,
            object_ambient_scale: self.object_ambient_scale,
            object_albedo_saturation: self.object_albedo_saturation,
            terrain_metallicness: self.terrain_metallicness,
            terrain_roughness_scale: self.terrain_roughness_scale,
            terrain_light_scale: self.terrain_light_scale,
            terrain_ambient_scale: self.terrain_ambient_scale,
            terrain_albedo_saturation: self.terrain_albedo_saturation,
            terrain_lod_noise_scale: self.terrain_lod_noise_scale,
            terrain_lod_noise_tile: self.terrain_lod_noise_tile,
        };
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PresetVisualSettingsV1 {
    omv_enabled: bool,
    native_pbr: PresetNativePbrV1,
    native_sky: NativeSkyConfig,
    embedded_effects: EmbeddedEffectsConfig,
}

impl PresetVisualSettingsV1 {
    fn capture(config: &GraphicsMenuConfig) -> Self {
        Self {
            omv_enabled: config.screen_space_shaders,
            native_pbr: config.native_pbr.into(),
            native_sky: config.native_sky,
            embedded_effects: config.embedded_effects,
        }
    }

    fn apply(self, target: &mut GraphicsMenuConfig) {
        target.screen_space_shaders = self.omv_enabled;
        self.native_pbr.apply(&mut target.native_pbr);
        target.native_sky = self.native_sky;
        target.embedded_effects = self.embedded_effects;
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LutDependencyV1 {
    file_name: String,
    revision: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExternalShaderPresetV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    shader_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    shader_version: Option<String>,
    file_name: String,
    source_revision: String,
    enabled: bool,
    phase: ShaderPhase,
    passes: u32,
    options: Vec<ExternalShaderOptionV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExternalShaderOptionV1 {
    key: String,
    value: ExternalShaderOptionValueV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
enum ExternalShaderOptionValueV1 {
    Float(f32),
    Integer(i32),
    Bool(bool),
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PresetDependenciesV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lut: Option<LutDependencyV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    external_shaders: Vec<ExternalShaderPresetV1>,
}

#[derive(Clone, Debug, Serialize)]
struct PresetFileV1 {
    format: &'static str,
    preset_format_version: u32,
    config_schema_version: u32,
    preset: PresetMetadata,
    settings: PresetVisualSettingsV1,
    #[serde(skip_serializing_if = "dependencies_are_empty")]
    dependencies: PresetDependenciesV1,
}

fn dependencies_are_empty(dependencies: &PresetDependenciesV1) -> bool {
    dependencies.lut.is_none() && dependencies.external_shaders.is_empty()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPresetFile {
    format: String,
    preset_format_version: u32,
    config_schema_version: u32,
    preset: PresetMetadata,
    settings: toml::Value,
    #[serde(default)]
    dependencies: PresetDependenciesV1,
}

#[derive(Clone, Debug)]
pub(crate) struct PresetDocument {
    pub(crate) metadata: PresetMetadata,
    settings: PresetVisualSettingsV1,
    dependencies: PresetDependenciesV1,
}

impl PresetDocument {
    pub(crate) fn key(&self) -> PresetKey {
        PresetKey {
            id: self.metadata.id.clone(),
            version: self.metadata.version.clone(),
        }
    }

    pub(crate) fn apply(
        &self,
        menu_config: &mut GraphicsMenuConfig,
        sources: &mut [ScreenShaderSource],
        luts: &LutCatalog,
    ) -> Result<()> {
        validate_visual_settings(&self.settings)?;
        validate_lut_dependency(&self.settings, &self.dependencies, luts)?;
        let mut candidate_sources = sources.to_vec();
        apply_external_shaders(&self.dependencies.external_shaders, &mut candidate_sources)?;

        let mut candidate_config = *menu_config;
        self.settings.apply(&mut candidate_config);
        menu_config.clone_from(&candidate_config);
        sources.clone_from_slice(&candidate_sources);
        Ok(())
    }

    pub(crate) fn payload_revision(&self) -> Result<u64> {
        payload_revision(&self.settings, &self.dependencies)
    }

    pub(crate) fn matches_current(
        &self,
        menu_config: &GraphicsMenuConfig,
        sources: &[ScreenShaderSource],
        luts: &LutCatalog,
    ) -> Result<bool> {
        let mut expected_menu = *menu_config;
        let mut expected_sources = sources.to_vec();
        self.apply(&mut expected_menu, &mut expected_sources, luts)?;
        let current_settings = toml::Value::try_from(PresetVisualSettingsV1::capture(menu_config))?;
        let expected_settings =
            toml::Value::try_from(PresetVisualSettingsV1::capture(&expected_menu))?;
        Ok(current_settings == expected_settings
            && sources
                .iter()
                .zip(&expected_sources)
                .all(|(current, expected)| external_runtime_equal(current, expected)))
    }

    fn canonical_text(&self) -> Result<String> {
        let file = PresetFileV1 {
            format: PRESET_MAGIC,
            preset_format_version: PRESET_FORMAT_VERSION,
            config_schema_version: crate::config::CONFIG_SCHEMA_VERSION,
            preset: self.metadata.clone(),
            settings: self.settings,
            dependencies: self.dependencies.clone(),
        };
        toml::to_string_pretty(&file).context("failed to serialize preset")
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PresetCatalogEntry {
    pub(crate) display_name: String,
    pub(crate) version: String,
    pub(crate) author: String,
    pub(crate) description: String,
    pub(crate) search_key: String,
    pub(crate) document: Option<PresetDocument>,
    pub(crate) error: Option<String>,
    pub(crate) built_in: bool,
    pub(crate) path: Option<PathBuf>,
    pub(crate) content_hash: u64,
}

impl PresetCatalogEntry {
    pub(crate) fn key(&self) -> Option<PresetKey> {
        self.document.as_ref().map(PresetDocument::key)
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct PresetCatalog {
    pub(crate) entries: Vec<PresetCatalogEntry>,
}

#[derive(Clone, Debug)]
enum PresetPublishTarget {
    New,
    Update {
        path: PathBuf,
        source_key: PresetKey,
        expected_content_hash: u64,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct PresetPublishRequest {
    metadata: PresetMetadata,
    settings: PresetVisualSettingsV1,
    dependencies: PresetDependenciesV1,
    target: PresetPublishTarget,
}

impl PresetPublishRequest {
    pub(crate) fn capture(
        name: &str,
        version: &str,
        author: &str,
        description: &str,
        menu_config: &GraphicsMenuConfig,
        sources: &[ScreenShaderSource],
        luts: &LutCatalog,
    ) -> Result<Self> {
        let metadata = PresetMetadata {
            id: generate_uuid(),
            name: name.trim().to_owned(),
            version: version.trim().to_owned(),
            author: author.trim().to_owned(),
            description: description.trim().to_owned(),
            created_with: PresetBuildProvenance::current(),
        };
        validate_metadata(&metadata)?;
        let settings = PresetVisualSettingsV1::capture(menu_config);
        validate_visual_settings(&settings)?;
        let dependencies = PresetDependenciesV1 {
            lut: capture_lut_dependency(&settings, luts)?,
            external_shaders: capture_external_shaders(sources)?,
        };
        Ok(Self {
            metadata,
            settings,
            dependencies,
            target: PresetPublishTarget::New,
        })
    }

    pub(crate) fn capture_new_version(
        source: &PresetDocument,
        source_path: &Path,
        source_content_hash: u64,
        version: &str,
        menu_config: &GraphicsMenuConfig,
        sources: &[ScreenShaderSource],
        luts: &LutCatalog,
    ) -> Result<Self> {
        let version = version.trim();
        validate_newer_version(&source.metadata.version, version)?;
        let metadata = PresetMetadata {
            id: source.metadata.id.clone(),
            name: source.metadata.name.clone(),
            version: version.to_owned(),
            author: source.metadata.author.clone(),
            description: source.metadata.description.clone(),
            created_with: PresetBuildProvenance::current(),
        };
        validate_metadata(&metadata)?;
        let settings = PresetVisualSettingsV1::capture(menu_config);
        validate_visual_settings(&settings)?;
        let dependencies = PresetDependenciesV1 {
            lut: capture_lut_dependency(&settings, luts)?,
            external_shaders: capture_external_shaders(sources)?,
        };
        Ok(Self {
            metadata,
            settings,
            dependencies,
            target: PresetPublishTarget::Update {
                path: source_path.to_owned(),
                source_key: source.key(),
                expected_content_hash: source_content_hash,
            },
        })
    }

    fn into_parts(self) -> (PresetDocument, PresetPublishTarget) {
        (
            PresetDocument {
                metadata: self.metadata,
                settings: self.settings,
                dependencies: self.dependencies,
            },
            self.target,
        )
    }
}

pub(crate) fn suggest_next_patch_version(version: &str) -> String {
    let Ok(version) = Version::parse(version) else {
        return "1.0.0".to_owned();
    };
    if let Some(patch) = version.patch.checked_add(1) {
        format!("{}.{}.{}", version.major, version.minor, patch)
    } else if let Some(minor) = version.minor.checked_add(1) {
        format!("{}.{}.0", version.major, minor)
    } else if let Some(major) = version.major.checked_add(1) {
        format!("{major}.0.0")
    } else {
        version.to_string()
    }
}

fn validate_newer_version(current: &str, candidate: &str) -> Result<()> {
    validate_semver(candidate)?;
    let current = Version::parse(current).context("current preset version is invalid")?;
    let candidate = Version::parse(candidate).context("new preset version is invalid")?;
    if candidate.cmp_precedence(&current).is_le() {
        bail!("new preset version must be newer than {current}");
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PresetActiveState {
    state_format_version: u32,
    pub(crate) preset_id: String,
    pub(crate) preset_version: String,
    pub(crate) preset_payload_revision: String,
}

impl PresetActiveState {
    pub(crate) fn new(key: &PresetKey, payload_revision: u64) -> Self {
        Self {
            state_format_version: 1,
            preset_id: key.id.clone(),
            preset_version: key.version.clone(),
            preset_payload_revision: format!("{payload_revision:016x}"),
        }
    }

    pub(crate) fn key(&self) -> PresetKey {
        PresetKey {
            id: self.preset_id.clone(),
            version: self.preset_version.clone(),
        }
    }

    pub(crate) fn payload_revision(&self) -> Result<u64> {
        validate_revision(&self.preset_payload_revision)
    }
}

pub(crate) enum PresetEvent {
    Catalog(PresetCatalog),
    Published(PresetKey),
    ActiveState(Option<PresetActiveState>),
    Error(String),
}

enum PresetCommand {
    Refresh,
    Publish(PresetPublishRequest),
    RecordActiveState(Option<PresetActiveState>),
    Stop,
}

pub(crate) struct PresetService {
    sender: SyncSender<PresetCommand>,
    receiver: Receiver<PresetEvent>,
    worker: thread::Thread,
}

impl PresetService {
    pub(crate) fn start() -> Result<Self> {
        let (command_sender, command_receiver) = sync_channel(4);
        let (event_sender, event_receiver) = sync_channel(4);
        let handle = thread::Builder::new()
            .name("omv-presets".to_owned())
            .spawn(move || preset_worker(command_receiver, event_sender))
            .context("failed to start preset catalog worker")?;
        let worker = handle.thread().clone();
        drop(handle);
        Ok(Self {
            sender: command_sender,
            receiver: event_receiver,
            worker,
        })
    }

    pub(crate) fn request_refresh(&self) -> Result<()> {
        self.send(PresetCommand::Refresh)
    }

    pub(crate) fn request_publish(&self, request: PresetPublishRequest) -> Result<()> {
        self.send(PresetCommand::Publish(request))
    }

    pub(crate) fn record_active_state(&self, state: Option<PresetActiveState>) -> Result<()> {
        self.send(PresetCommand::RecordActiveState(state))
    }

    pub(crate) fn try_take_events(&self) -> Vec<PresetEvent> {
        let mut events = Vec::new();
        loop {
            match self.receiver.try_recv() {
                Ok(event) => events.push(event),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return events,
            }
        }
    }

    fn send(&self, command: PresetCommand) -> Result<()> {
        match self.sender.try_send(command) {
            Ok(()) => {
                self.worker.unpark();
                Ok(())
            }
            Err(TrySendError::Full(_)) => bail!("preset worker is busy"),
            Err(TrySendError::Disconnected(_)) => bail!("preset worker is unavailable"),
        }
    }
}

impl Drop for PresetService {
    fn drop(&mut self) {
        let _ = self.sender.try_send(PresetCommand::Stop);
        self.worker.unpark();
    }
}

fn preset_worker(receiver: Receiver<PresetCommand>, sender: SyncSender<PresetEvent>) {
    publish_catalog(&sender);
    match load_active_state() {
        Ok(state) => {
            if sender.send(PresetEvent::ActiveState(state)).is_err() {
                return;
            }
        }
        Err(err) => {
            if sender
                .send(PresetEvent::Error(format!(
                    "active preset state was ignored: {err:#}"
                )))
                .is_err()
            {
                return;
            }
        }
    }
    while let Ok(command) = receiver.recv() {
        match command {
            PresetCommand::Refresh => publish_catalog(&sender),
            PresetCommand::Publish(request) => {
                let result = publish_user_preset(request);
                match result {
                    Ok(key) => {
                        if sender.send(PresetEvent::Published(key)).is_err() {
                            return;
                        }
                        publish_catalog(&sender);
                    }
                    Err(err) => {
                        if sender.send(PresetEvent::Error(format!("{err:#}"))).is_err() {
                            return;
                        }
                    }
                }
            }
            PresetCommand::RecordActiveState(state) => {
                if let Err(err) = save_active_state(state.as_ref())
                    && sender
                        .send(PresetEvent::Error(format!(
                            "could not record active preset: {err:#}"
                        )))
                        .is_err()
                {
                    return;
                }
            }
            PresetCommand::Stop => return,
        }
    }
}

fn payload_revision(
    settings: &PresetVisualSettingsV1,
    dependencies: &PresetDependenciesV1,
) -> Result<u64> {
    #[derive(Serialize)]
    struct Payload<'a> {
        settings: &'a PresetVisualSettingsV1,
        dependencies: &'a PresetDependenciesV1,
    }
    let text = toml::to_string(&Payload {
        settings,
        dependencies,
    })
    .context("failed to serialize preset payload")?;
    Ok(fingerprint(text.as_bytes()))
}

fn load_active_state() -> Result<Option<PresetActiveState>> {
    let text = match fs::read_to_string(PRESET_STATE_PATH) {
        Ok(text) => text,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to read {PRESET_STATE_PATH}"));
        }
    };
    let state: PresetActiveState =
        toml::from_str(&text).with_context(|| format!("failed to parse {PRESET_STATE_PATH}"))?;
    if state.state_format_version != 1 {
        bail!(
            "active preset state version {} is unsupported",
            state.state_format_version
        );
    }
    validate_uuid(&state.preset_id)?;
    validate_semver(&state.preset_version)?;
    state.payload_revision()?;
    Ok(Some(state))
}

fn save_active_state(state: Option<&PresetActiveState>) -> Result<()> {
    let path = Path::new(PRESET_STATE_PATH);
    let Some(state) = state else {
        match fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                return Err(err).with_context(|| format!("failed to remove {}", path.display()));
            }
        }
    };
    let text = toml::to_string_pretty(state).context("failed to serialize active preset state")?;
    crate::file_io::atomic_write_text(path, &text)
}

fn publish_catalog(sender: &SyncSender<PresetEvent>) {
    let event = match scan_catalog() {
        Ok(catalog) => PresetEvent::Catalog(catalog),
        Err(err) => PresetEvent::Error(format!("failed to scan presets: {err:#}")),
    };
    let _ = sender.send(event);
}

fn scan_catalog() -> Result<PresetCatalog> {
    let built_in = builtin_default_preset()?;
    let built_in_text = built_in.canonical_text()?;
    let mut entries = vec![valid_catalog_entry(
        built_in,
        None,
        true,
        fingerprint(built_in_text.as_bytes()),
    )];

    let mut paths = Vec::new();
    collect_preset_files(Path::new(PRESET_DIRECTORY), 0, &mut paths)?;
    paths.sort_by_key(|path| path.to_string_lossy().to_ascii_lowercase());

    for path in paths {
        let entry = match read_preset_file(&path) {
            Ok((document, content_hash)) => {
                valid_catalog_entry(document, Some(path), false, content_hash)
            }
            Err(err) => PresetCatalogEntry {
                display_name: path
                    .file_stem()
                    .and_then(|name| name.to_str())
                    .unwrap_or("Invalid preset")
                    .to_owned(),
                version: String::new(),
                author: String::new(),
                description: String::new(),
                search_key: path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("invalid preset")
                    .to_ascii_lowercase(),
                document: None,
                error: Some(format!("{err:#}")),
                built_in: false,
                path: Some(path),
                content_hash: 0,
            },
        };
        entries.push(entry);
    }

    mark_duplicate_conflicts(&mut entries);
    entries.sort_by(|left, right| {
        left.display_name
            .to_ascii_lowercase()
            .cmp(&right.display_name.to_ascii_lowercase())
            .then_with(|| left.version.cmp(&right.version))
            .then_with(|| right.built_in.cmp(&left.built_in))
    });
    Ok(PresetCatalog { entries })
}

fn valid_catalog_entry(
    document: PresetDocument,
    path: Option<PathBuf>,
    built_in: bool,
    content_hash: u64,
) -> PresetCatalogEntry {
    let search_key = format!(
        "{}\n{}",
        document.metadata.name.to_ascii_lowercase(),
        document.metadata.author.to_ascii_lowercase()
    );
    PresetCatalogEntry {
        display_name: document.metadata.name.clone(),
        version: document.metadata.version.clone(),
        author: document.metadata.author.clone(),
        description: document.metadata.description.clone(),
        search_key,
        document: Some(document),
        error: None,
        built_in,
        path,
        content_hash,
    }
}

fn mark_duplicate_conflicts(entries: &mut [PresetCatalogEntry]) {
    let mut groups: BTreeMap<PresetKey, Vec<usize>> = BTreeMap::new();
    for (index, entry) in entries.iter().enumerate() {
        if let Some(key) = entry.key() {
            groups.entry(key).or_default().push(index);
        }
    }

    for (key, indexes) in groups {
        if indexes.len() < 2 {
            continue;
        }
        let first_hash = entries[indexes[0]].content_hash;
        if indexes
            .iter()
            .all(|index| entries[*index].content_hash == first_hash)
        {
            for index in indexes.into_iter().skip(1) {
                entries[index].error = Some("duplicate of an identical preset".to_owned());
                entries[index].document = None;
            }
            continue;
        }

        let message = format!(
            "conflicting files use preset ID {} version {}; neither can be activated",
            key.id, key.version
        );
        for index in indexes {
            entries[index].error = Some(message.clone());
            entries[index].document = None;
        }
    }
}

fn collect_preset_files(directory: &Path, depth: usize, output: &mut Vec<PathBuf>) -> Result<()> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("read {}", directory.display())),
    };
    for entry in entries {
        let entry = entry.with_context(|| format!("enumerate {}", directory.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspect {}", entry.path().display()))?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            if depth < MAX_PRESET_SCAN_DEPTH {
                collect_preset_files(&entry.path(), depth + 1, output)?;
            }
            continue;
        }
        let path = entry.path();
        if file_type.is_file()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.to_ascii_lowercase().ends_with(PRESET_SUFFIX))
        {
            output.push(path);
        }
    }
    Ok(())
}

fn read_preset_file(path: &Path) -> Result<(PresetDocument, u64)> {
    let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if !metadata.is_file() {
        bail!("not a regular file");
    }
    if metadata.len() > MAX_PRESET_BYTES {
        bail!(
            "preset exceeds the {} KiB safety limit",
            MAX_PRESET_BYTES / 1024
        );
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("read UTF-8 preset {}", path.display()))?;
    let document =
        parse_preset(&text).with_context(|| format!("invalid preset {}", path.display()))?;
    Ok((document, fingerprint(text.as_bytes())))
}

fn parse_preset(text: &str) -> Result<PresetDocument> {
    if text.len() as u64 > MAX_PRESET_BYTES {
        bail!("preset exceeds the size limit");
    }
    let raw_value = text
        .parse::<toml::Value>()
        .context("preset is not valid TOML")?;
    reject_non_finite(&raw_value, "preset")?;
    let raw: RawPresetFile = raw_value
        .clone()
        .try_into()
        .context("preset envelope does not match its declared format")?;
    if raw.format != PRESET_MAGIC {
        bail!("unsupported preset format '{}'", raw.format);
    }
    if raw.preset_format_version != PRESET_FORMAT_VERSION {
        bail!(
            "preset format version {} is unsupported; this OMV supports version {}",
            raw.preset_format_version,
            PRESET_FORMAT_VERSION
        );
    }
    validate_metadata(&raw.preset)?;

    validate_frozen_schema(raw.config_schema_version, &raw.settings)?;
    let migrated = migrate_settings(raw.config_schema_version, raw.settings)?;
    validate_exact_shape(&migrated, &schema_v1_shape()?, "settings")?;
    let settings: PresetVisualSettingsV1 = migrated
        .try_into()
        .context("preset settings do not match config schema 1")?;
    validate_visual_settings(&settings)?;
    validate_dependencies(&raw.dependencies)?;
    Ok(PresetDocument {
        metadata: raw.preset,
        settings,
        dependencies: raw.dependencies,
    })
}

fn validate_frozen_schema(version: u32, settings: &toml::Value) -> Result<()> {
    let manifest = match version {
        1 => include_str!("../presets/schema_v1.fields"),
        0 => bail!("preset config schema 0 was never a released preset schema"),
        version if version > crate::config::CONFIG_SCHEMA_VERSION => bail!(
            "preset config schema {version} is newer than supported schema {}",
            crate::config::CONFIG_SCHEMA_VERSION
        ),
        version => bail!("preset config schema {version} has no frozen field manifest"),
    };
    let expected: BTreeSet<_> = manifest.lines().filter(|line| !line.is_empty()).collect();
    let mut actual = BTreeSet::new();
    collect_leaf_paths(settings, "settings", &mut actual);
    for missing in &expected {
        if !actual.iter().any(|actual| actual.as_str() == *missing) {
            bail!("missing preset setting '{missing}'");
        }
    }
    for unknown in &actual {
        if !expected
            .iter()
            .any(|expected| *expected == unknown.as_str())
        {
            bail!("unknown preset setting '{unknown}'");
        }
    }
    Ok(())
}

fn collect_leaf_paths(value: &toml::Value, path: &str, output: &mut BTreeSet<String>) {
    match value {
        toml::Value::Table(table) => {
            for (key, value) in table {
                collect_leaf_paths(value, &format!("{path}.{key}"), output);
            }
        }
        toml::Value::Array(_) => {
            output.insert(format!("{path}[]"));
        }
        _ => {
            output.insert(path.to_owned());
        }
    }
}

fn migrate_settings(version: u32, settings: toml::Value) -> Result<toml::Value> {
    match version {
        crate::config::CONFIG_SCHEMA_VERSION => Ok(settings),
        0 => bail!("preset config schema 0 was never a released preset schema"),
        version if version > crate::config::CONFIG_SCHEMA_VERSION => bail!(
            "preset config schema {version} is newer than supported schema {}",
            crate::config::CONFIG_SCHEMA_VERSION
        ),
        version => bail!("preset config schema {version} has no registered migration"),
    }
}

fn schema_v1_shape() -> Result<toml::Value> {
    let shipped: PsychoGraphicsConfig = toml::from_str(include_str!("../config/omv.toml"))
        .context("shipped OMV configuration is invalid")?;
    let menu = GraphicsMenuConfig::from(&shipped);
    toml::Value::try_from(PresetVisualSettingsV1::capture(&menu))
        .context("failed to construct config schema 1 shape")
}

fn validate_exact_shape(actual: &toml::Value, expected: &toml::Value, path: &str) -> Result<()> {
    match (actual, expected) {
        (toml::Value::Table(actual), toml::Value::Table(expected)) => {
            for key in actual.keys() {
                if !expected.contains_key(key) {
                    bail!("unknown preset setting '{path}.{key}'");
                }
            }
            for (key, expected_value) in expected {
                let next_path = format!("{path}.{key}");
                let actual_value = actual
                    .get(key)
                    .ok_or_else(|| anyhow!("missing preset setting '{next_path}'"))?;
                validate_exact_shape(actual_value, expected_value, &next_path)?;
            }
            Ok(())
        }
        (toml::Value::Array(actual), toml::Value::Array(expected)) => {
            if expected.is_empty() {
                return Ok(());
            }
            for (index, actual_value) in actual.iter().enumerate() {
                validate_exact_shape(actual_value, &expected[0], &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        (actual, expected)
            if std::mem::discriminant(actual) == std::mem::discriminant(expected) =>
        {
            Ok(())
        }
        _ => bail!("preset setting '{path}' has the wrong value type"),
    }
}

fn reject_non_finite(value: &toml::Value, path: &str) -> Result<()> {
    match value {
        toml::Value::Float(value) if !value.is_finite() => {
            bail!("'{path}' must be finite")
        }
        toml::Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                reject_non_finite(value, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        toml::Value::Table(table) => {
            for (key, value) in table {
                reject_non_finite(value, &format!("{path}.{key}"))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_visual_settings(settings: &PresetVisualSettingsV1) -> Result<()> {
    let pbr = settings.native_pbr;
    validate_float_range(
        "settings.native_pbr.object_roughness_scale",
        pbr.object_roughness_scale,
        0.05,
        4.0,
    )?;
    validate_float_range(
        "settings.native_pbr.object_light_scale",
        pbr.object_light_scale,
        0.0,
        4.0,
    )?;
    validate_float_range(
        "settings.native_pbr.object_ambient_scale",
        pbr.object_ambient_scale,
        0.0,
        4.0,
    )?;
    validate_float_range(
        "settings.native_pbr.object_albedo_saturation",
        pbr.object_albedo_saturation,
        0.0,
        2.0,
    )?;
    validate_float_range(
        "settings.native_pbr.terrain_metallicness",
        pbr.terrain_metallicness,
        0.0,
        1.0,
    )?;
    validate_float_range(
        "settings.native_pbr.terrain_roughness_scale",
        pbr.terrain_roughness_scale,
        0.05,
        4.0,
    )?;
    validate_float_range(
        "settings.native_pbr.terrain_light_scale",
        pbr.terrain_light_scale,
        0.0,
        4.0,
    )?;
    validate_float_range(
        "settings.native_pbr.terrain_ambient_scale",
        pbr.terrain_ambient_scale,
        0.0,
        4.0,
    )?;
    validate_float_range(
        "settings.native_pbr.terrain_albedo_saturation",
        pbr.terrain_albedo_saturation,
        0.0,
        2.0,
    )?;
    validate_float_range(
        "settings.native_pbr.terrain_lod_noise_scale",
        pbr.terrain_lod_noise_scale,
        0.0,
        1.0,
    )?;
    validate_float_range(
        "settings.native_pbr.terrain_lod_noise_tile",
        pbr.terrain_lod_noise_tile,
        0.05,
        16.0,
    )?;

    let sky = settings.native_sky;
    validate_float_range(
        "settings.native_sky.atmosphere_thickness",
        sky.atmosphere_thickness,
        0.0,
        8.0,
    )?;
    validate_float_range(
        "settings.native_sky.sun_influence",
        sky.sun_influence,
        0.05,
        8.0,
    )?;
    validate_float_range(
        "settings.native_sky.sun_strength",
        sky.sun_strength,
        0.0,
        8.0,
    )?;
    validate_float_range(
        "settings.native_sky.glare_strength",
        sky.glare_strength,
        0.0,
        8.0,
    )?;
    validate_float_range(
        "settings.native_sky.sky_multiplier",
        sky.sky_multiplier,
        0.0,
        4.0,
    )?;
    validate_float_range(
        "settings.native_sky.cloud_transparency",
        sky.cloud_transparency,
        0.05,
        1.0,
    )?;
    validate_float_range(
        "settings.native_sky.cloud_brightness",
        sky.cloud_brightness,
        0.0,
        4.0,
    )?;
    validate_float_range(
        "settings.native_sky.star_strength",
        sky.star_strength,
        0.0,
        8.0,
    )?;
    validate_float_range(
        "settings.native_sky.star_twinkle",
        sky.star_twinkle,
        0.0,
        8.0,
    )?;
    validate_float_range("settings.native_sky.sunset_red", sky.sunset_red, 0.0, 4.0)?;
    validate_float_range(
        "settings.native_sky.sunset_green",
        sky.sunset_green,
        0.0,
        4.0,
    )?;
    validate_float_range("settings.native_sky.sunset_blue", sky.sunset_blue, 0.0, 4.0)?;

    for source in merge_embedded_sources_with_luts(&settings.embedded_effects, &[], &[], Vec::new())
    {
        for option in &source.options {
            let path = format!("embedded effect '{}' option '{}'", source.name, option.key);
            match option.value {
                ShaderOptionValue::Float(value) => {
                    validate_float_range(&path, value, option.min, option.max)?;
                }
                ShaderOptionValue::Integer(value)
                    if !(option.min.round() as i32..=option.max.round() as i32)
                        .contains(&value) =>
                {
                    bail!(
                        "{path} is out of range; expected {} through {}, got {value}",
                        option.min.round() as i32,
                        option.max.round() as i32
                    );
                }
                ShaderOptionValue::Integer(_) | ShaderOptionValue::Bool(_) => {}
            }
        }
    }
    Ok(())
}

fn validate_float_range(path: &str, value: f32, min: f32, max: f32) -> Result<()> {
    if !value.is_finite() {
        bail!("{path} must be finite");
    }
    if !(min..=max).contains(&value) {
        bail!("{path} is out of range; expected {min} through {max}, got {value}");
    }
    Ok(())
}

fn validate_metadata(metadata: &PresetMetadata) -> Result<()> {
    validate_uuid(&metadata.id)?;
    validate_text("preset name", &metadata.name, 1, 80)?;
    validate_semver(&metadata.version)?;
    validate_text("preset author", &metadata.author, 0, 80)?;
    validate_text("preset description", &metadata.description, 0, 512)?;
    validate_build_provenance(&metadata.created_with)?;
    Ok(())
}

fn validate_build_provenance(provenance: &PresetBuildProvenance) -> Result<()> {
    validate_semver(&provenance.omv_version).context("created-with OMV version is not semantic")?;
    if provenance.git_commit != "unknown"
        && (!matches!(provenance.git_commit.len(), 40 | 64)
            || !provenance
                .git_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()))
    {
        bail!("created-with Git commit must be a full hexadecimal object ID");
    }
    validate_text("created-with Git tag", &provenance.git_tag, 0, 255)?;
    validate_text("created-with Git branch", &provenance.git_branch, 1, 255)?;
    Ok(())
}

fn validate_text(field: &str, value: &str, min: usize, max: usize) -> Result<()> {
    let length = value.chars().count();
    if length < min || length > max {
        bail!("{field} must contain between {min} and {max} characters");
    }
    if value.chars().any(char::is_control) {
        bail!("{field} contains a control character");
    }
    Ok(())
}

fn validate_uuid(value: &str) -> Result<()> {
    if value.len() != 36
        || value.bytes().enumerate().any(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte != b'-',
            _ => !byte.is_ascii_hexdigit(),
        })
    {
        bail!("preset ID must be a canonical UUID");
    }
    Ok(())
}

fn validate_semver(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 64 || !value.is_ascii() {
        bail!("preset version must be an ASCII semantic version");
    }
    let (without_build, build) = split_once_optional(value, '+');
    if let Some(build) = build {
        validate_identifiers(build, false, "build metadata")?;
    }
    let (core, prerelease) = split_once_optional(without_build, '-');
    if let Some(prerelease) = prerelease {
        validate_identifiers(prerelease, true, "prerelease")?;
    }
    let components: Vec<_> = core.split('.').collect();
    if components.len() != 3
        || components
            .iter()
            .any(|component| !valid_numeric_identifier(component))
    {
        bail!("preset version must use major.minor.patch semantic versioning");
    }
    Ok(())
}

fn split_once_optional(value: &str, separator: char) -> (&str, Option<&str>) {
    value
        .split_once(separator)
        .map_or((value, None), |(left, right)| (left, Some(right)))
}

fn valid_numeric_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

fn validate_identifiers(value: &str, reject_numeric_leading_zero: bool, field: &str) -> Result<()> {
    if value.is_empty() {
        bail!("semantic-version {field} is empty");
    }
    for identifier in value.split('.') {
        if identifier.is_empty()
            || !identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || (reject_numeric_leading_zero
                && identifier.bytes().all(|byte| byte.is_ascii_digit())
                && !valid_numeric_identifier(identifier))
        {
            bail!("semantic-version {field} contains an invalid identifier");
        }
    }
    Ok(())
}

fn validate_dependencies(dependencies: &PresetDependenciesV1) -> Result<()> {
    if let Some(lut) = dependencies.lut.as_ref() {
        validate_text("LUT filename", &lut.file_name, 1, 255)?;
        validate_revision(&lut.revision)?;
        if Path::new(&lut.file_name)
            .file_name()
            .and_then(|name| name.to_str())
            != Some(lut.file_name.as_str())
        {
            bail!("LUT dependency must contain a filename, not a path");
        }
    }

    let mut identities = BTreeMap::new();
    for shader in &dependencies.external_shaders {
        validate_text("shader filename", &shader.file_name, 1, 255)?;
        if Path::new(&shader.file_name)
            .file_name()
            .and_then(|name| name.to_str())
            != Some(shader.file_name.as_str())
        {
            bail!("shader dependency must contain a filename, not a path");
        }
        validate_revision(&shader.source_revision)?;
        if !(1..=8).contains(&shader.passes) {
            bail!("external shader pass count must be between 1 and 8");
        }
        if let Some(id) = shader.shader_id.as_deref() {
            validate_uuid(id)?;
        }
        if let Some(version) = shader.shader_version.as_deref() {
            validate_semver(version)?;
        }
        let identity = shader_identity(shader);
        if identities.insert(identity.clone(), ()).is_some() {
            bail!("external shader dependency '{identity}' is duplicated");
        }
        let mut option_keys = BTreeMap::new();
        for option in &shader.options {
            validate_text("shader option key", &option.key, 1, 128)?;
            if option_keys.insert(option.key.as_str(), ()).is_some() {
                bail!(
                    "external shader '{}' repeats option '{}'",
                    shader.file_name,
                    option.key
                );
            }
            if let ExternalShaderOptionValueV1::Float(value) = option.value
                && !value.is_finite()
            {
                bail!(
                    "external shader '{}' option '{}' is not finite",
                    shader.file_name,
                    option.key
                );
            }
        }
    }
    Ok(())
}

fn validate_revision(revision: &str) -> Result<u64> {
    if revision.len() != 16 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("content revision must contain exactly 16 hexadecimal digits");
    }
    u64::from_str_radix(revision, 16).context("invalid content revision")
}

fn capture_lut_dependency(
    settings: &PresetVisualSettingsV1,
    luts: &LutCatalog,
) -> Result<Option<LutDependencyV1>> {
    let grade = settings.embedded_effects.color_grade;
    if !grade.lut_enabled {
        return Ok(None);
    }
    let asset = luts
        .assets
        .iter()
        .find(|asset| asset.id == grade.lut_file_id)
        .ok_or_else(|| {
            anyhow!(
                "selected LUT ID {} is unavailable; cannot create an exact preset",
                grade.lut_file_id
            )
        })?;
    Ok(Some(LutDependencyV1 {
        file_name: asset.file_name.clone(),
        revision: format!("{:016x}", asset.revision),
    }))
}

fn validate_lut_dependency(
    settings: &PresetVisualSettingsV1,
    dependencies: &PresetDependenciesV1,
    luts: &LutCatalog,
) -> Result<()> {
    let grade = settings.embedded_effects.color_grade;
    if !grade.lut_enabled {
        return Ok(());
    }
    let dependency = dependencies
        .lut
        .as_ref()
        .ok_or_else(|| anyhow!("preset enables a LUT but declares no LUT dependency"))?;
    let revision = validate_revision(&dependency.revision)?;
    let asset = luts
        .assets
        .iter()
        .find(|asset| {
            asset.file_name.eq_ignore_ascii_case(&dependency.file_name)
                && asset.revision == revision
        })
        .ok_or_else(|| {
            anyhow!(
                "required LUT '{}' revision {} is not installed",
                dependency.file_name,
                dependency.revision
            )
        })?;
    if asset.id != grade.lut_file_id {
        bail!(
            "LUT dependency '{}' does not match the preset's selected LUT ID",
            dependency.file_name
        );
    }
    Ok(())
}

fn capture_external_shaders(sources: &[ScreenShaderSource]) -> Result<Vec<ExternalShaderPresetV1>> {
    let mut shaders = Vec::new();
    for source in sources.iter().filter(|source| source.is_external_file()) {
        if let Some(error) = source.shader_error.as_deref() {
            bail!(
                "external shader '{}' is not loadable and cannot be captured: {error}",
                source.name
            );
        }
        if source.source_revision == 0 {
            bail!(
                "external shader '{}' has no verified source revision",
                source.name
            );
        }
        let file_name = source
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow!("external shader '{}' has an invalid filename", source.name))?
            .to_owned();
        let options = source
            .options
            .iter()
            .map(|option| ExternalShaderOptionV1 {
                key: option.key.clone(),
                value: match option.value {
                    ShaderOptionValue::Float(value) => ExternalShaderOptionValueV1::Float(value),
                    ShaderOptionValue::Integer(value) => {
                        ExternalShaderOptionValueV1::Integer(value)
                    }
                    ShaderOptionValue::Bool(value) => ExternalShaderOptionValueV1::Bool(value),
                },
            })
            .collect();
        shaders.push(ExternalShaderPresetV1 {
            shader_id: source.shader_id.clone(),
            shader_version: source.shader_version.clone(),
            file_name,
            source_revision: format!("{:016x}", source.source_revision),
            enabled: source.enabled,
            phase: source.phase,
            passes: source.pass_count,
            options,
        });
    }
    shaders.sort_by_key(shader_identity);
    validate_dependencies(&PresetDependenciesV1 {
        lut: None,
        external_shaders: shaders.clone(),
    })?;
    Ok(shaders)
}

fn apply_external_shaders(
    preset_shaders: &[ExternalShaderPresetV1],
    sources: &mut [ScreenShaderSource],
) -> Result<()> {
    let mut matches = Vec::with_capacity(preset_shaders.len());
    for preset in preset_shaders {
        let expected_revision = validate_revision(&preset.source_revision)?;
        let candidates: Vec<_> = sources
            .iter()
            .enumerate()
            .filter(|(_, source)| {
                source.is_external_file()
                    && source.shader_error.is_none()
                    && source.source_revision == expected_revision
                    && preset
                        .shader_version
                        .as_deref()
                        .is_none_or(|version| source.shader_version.as_deref() == Some(version))
                    && match preset.shader_id.as_deref() {
                        Some(id) => source.shader_id.as_deref() == Some(id),
                        None => source
                            .path
                            .file_name()
                            .and_then(|name| name.to_str())
                            .is_some_and(|name| name.eq_ignore_ascii_case(&preset.file_name)),
                    }
            })
            .map(|(index, _)| index)
            .collect();
        if candidates.len() != 1 {
            bail!(
                "external shader '{}' revision {} has {} matching installations; exactly one is required",
                preset.file_name,
                preset.source_revision,
                candidates.len()
            );
        }
        let index = candidates[0];
        validate_external_options(preset, &sources[index])?;
        matches.push(index);
    }

    for source in sources
        .iter_mut()
        .filter(|source| source.is_external_file())
    {
        source.enabled = false;
    }
    for (preset, index) in preset_shaders.iter().zip(matches) {
        let source = &mut sources[index];
        source.enabled = preset.enabled;
        source.phase = preset.phase;
        source.set_pass_count(preset.passes)?;
        for option in &preset.options {
            let option_index = source
                .options
                .iter()
                .position(|candidate| candidate.key == option.key)
                .expect("external option was validated");
            match option.value {
                ExternalShaderOptionValueV1::Float(value) => {
                    source.set_option_float(option_index, value)?;
                }
                ExternalShaderOptionValueV1::Integer(value) => {
                    source.set_option_integer(option_index, value)?;
                }
                ExternalShaderOptionValueV1::Bool(value) => {
                    source.set_option_bool(option_index, value)?;
                }
            }
        }
    }
    Ok(())
}

fn validate_external_options(
    preset: &ExternalShaderPresetV1,
    source: &ScreenShaderSource,
) -> Result<()> {
    if preset.options.len() != source.options.len() {
        bail!(
            "external shader '{}' option schema changed (preset {}, installed {})",
            preset.file_name,
            preset.options.len(),
            source.options.len()
        );
    }
    for preset_option in &preset.options {
        let installed = source
            .options
            .iter()
            .find(|option| option.key == preset_option.key)
            .ok_or_else(|| {
                anyhow!(
                    "external shader '{}' has no option '{}'",
                    preset.file_name,
                    preset_option.key
                )
            })?;
        match (preset_option.value, &installed.value) {
            (ExternalShaderOptionValueV1::Float(value), ShaderOptionValue::Float(_))
                if value.is_finite() && (installed.min..=installed.max).contains(&value) => {}
            (ExternalShaderOptionValueV1::Integer(value), ShaderOptionValue::Integer(_))
                if (installed.min.round() as i32..=installed.max.round() as i32)
                    .contains(&value) => {}
            (ExternalShaderOptionValueV1::Bool(_), ShaderOptionValue::Bool(_)) => {}
            _ => bail!(
                "external shader '{}' option '{}' has an incompatible type or range",
                preset.file_name,
                preset_option.key
            ),
        }
    }
    Ok(())
}

fn external_runtime_equal(left: &ScreenShaderSource, right: &ScreenShaderSource) -> bool {
    if !left.is_external_file() && !right.is_external_file() {
        return true;
    }
    left.is_external_file() == right.is_external_file()
        && left.enabled == right.enabled
        && left.phase == right.phase
        && left.pass_count == right.pass_count
        && left.options.len() == right.options.len()
        && left
            .options
            .iter()
            .zip(&right.options)
            .all(|(left, right)| {
                left.key == right.key
                    && match (&left.value, &right.value) {
                        (ShaderOptionValue::Float(left), ShaderOptionValue::Float(right)) => {
                            left.to_bits() == right.to_bits()
                        }
                        (ShaderOptionValue::Integer(left), ShaderOptionValue::Integer(right)) => {
                            left == right
                        }
                        (ShaderOptionValue::Bool(left), ShaderOptionValue::Bool(right)) => {
                            left == right
                        }
                        _ => false,
                    }
            })
}

fn shader_identity(shader: &ExternalShaderPresetV1) -> String {
    shader.shader_id.clone().unwrap_or_else(|| {
        format!(
            "{}@{}",
            shader.file_name.to_ascii_lowercase(),
            shader.source_revision
        )
    })
}

fn builtin_default_preset() -> Result<PresetDocument> {
    let shipped: PsychoGraphicsConfig = toml::from_str(include_str!("../config/omv.toml"))
        .context("shipped OMV configuration is invalid")?;
    let settings = PresetVisualSettingsV1::capture(&GraphicsMenuConfig::from(&shipped));
    validate_visual_settings(&settings).context("shipped OMV preset settings are invalid")?;
    let lut_file_name = "01_mojave_natural.cube";
    let lut_revision = fingerprint(include_str!("../luts/01_mojave_natural.cube").as_bytes());
    let dependencies = if settings.embedded_effects.color_grade.lut_enabled {
        Some(LutDependencyV1 {
            file_name: lut_file_name.to_owned(),
            revision: format!("{lut_revision:016x}"),
        })
    } else {
        None
    };
    Ok(PresetDocument {
        metadata: PresetMetadata {
            id: DEFAULT_PRESET_ID.to_owned(),
            name: "OMV Default".to_owned(),
            version: DEFAULT_PRESET_VERSION.to_owned(),
            author: "OMV".to_owned(),
            description: "The immutable visual configuration shipped with OMV.".to_owned(),
            created_with: PresetBuildProvenance::current(),
        },
        settings,
        dependencies: PresetDependenciesV1 {
            lut: dependencies,
            external_shaders: Vec::new(),
        },
    })
}

fn publish_user_preset(request: PresetPublishRequest) -> Result<PresetKey> {
    let (document, target) = request.into_parts();
    validate_metadata(&document.metadata)?;
    validate_visual_settings(&document.settings)?;
    validate_dependencies(&document.dependencies)?;
    let text = document.canonical_text()?;
    if text.len() as u64 > MAX_PRESET_BYTES {
        bail!("serialized preset exceeds the size limit");
    }
    match target {
        PresetPublishTarget::New => {
            let directory = Path::new(PRESET_DIRECTORY);
            fs::create_dir_all(directory)
                .with_context(|| format!("failed to create {}", directory.display()))?;
            let path = next_new_preset_path(directory, &document.metadata)?;
            crate::file_io::atomic_create_text(&path, &text)?;
        }
        PresetPublishTarget::Update {
            path,
            source_key,
            expected_content_hash,
        } => {
            validate_update_target(&path)?;
            let (installed, current_content_hash) = read_preset_file(&path)?;
            if installed.key() != source_key {
                bail!(
                    "preset update target changed identity before publication: {}",
                    path.display()
                );
            }
            if current_content_hash != expected_content_hash {
                bail!(
                    "preset update target changed on disk before publication: {}",
                    path.display()
                );
            }
            if document.metadata.id != source_key.id {
                bail!("preset update cannot change its family ID");
            }
            crate::file_io::atomic_write_text(&path, &text)?;
        }
    }
    Ok(document.key())
}

fn validate_update_target(path: &Path) -> Result<()> {
    let relative = path
        .strip_prefix(Path::new(PRESET_DIRECTORY))
        .with_context(|| format!("preset update target is outside {PRESET_DIRECTORY}"))?;
    let component_count = relative.components().count();
    if component_count == 0
        || component_count > MAX_PRESET_SCAN_DEPTH + 1
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!(
            "preset update target has an invalid path: {}",
            path.display()
        );
    }
    if !path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.to_ascii_lowercase().ends_with(PRESET_SUFFIX))
    {
        bail!("preset update target has the wrong file extension");
    }
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("preset update target is not a regular file");
    }
    Ok(())
}

fn next_new_preset_path(directory: &Path, metadata: &PresetMetadata) -> Result<PathBuf> {
    for collision_index in 0..MAX_PRESET_NAME_ATTEMPTS {
        let path = directory.join(preset_file_name(metadata, collision_index));
        match fs::symlink_metadata(&path) {
            Ok(_) => continue,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(path),
            Err(err) => {
                return Err(err).with_context(|| format!("inspect {}", path.display()));
            }
        }
    }
    bail!(
        "could not find a free human-readable filename for preset '{}'",
        metadata.name
    )
}

fn preset_file_name(metadata: &PresetMetadata, collision_index: u32) -> String {
    let slug = preset_slug(&metadata.name);
    if collision_index == 0 {
        format!("{slug}{PRESET_SUFFIX}")
    } else {
        format!("{slug}-{}{PRESET_SUFFIX}", collision_index + 1)
    }
}

fn preset_slug(name: &str) -> String {
    let mut slug = String::new();
    let mut separator = false;
    for character in name.chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
            separator = false;
        } else if !separator && !slug.is_empty() {
            slug.push('-');
            separator = true;
        }
        if slug.len() >= 48 {
            break;
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        "preset".to_owned()
    } else {
        slug
    }
}

fn generate_uuid() -> String {
    let mut bytes = rand::random::<u128>().to_be_bytes();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn fingerprint(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn builtin_text() -> String {
        builtin_default_preset().unwrap().canonical_text().unwrap()
    }

    #[test]
    fn built_in_preset_round_trips_through_strict_schema_one() {
        let text = builtin_text();
        let parsed = parse_preset(&text).expect("parse built-in preset");
        assert_eq!(parsed.metadata.id, DEFAULT_PRESET_ID);
        assert_eq!(parsed.metadata.version, "1.0.0");
        assert!(parsed.dependencies.lut.is_some());
        assert_eq!(
            parsed.payload_revision().unwrap(),
            DEFAULT_PRESET_PAYLOAD_REVISION,
            "changing the built-in payload requires a new default preset version"
        );
    }

    #[test]
    fn versioned_preset_rejects_missing_unknown_and_future_settings() {
        let text = builtin_text();
        let missing = text.replace("omv_enabled = true\n", "");
        assert!(
            parse_preset(&missing)
                .unwrap_err()
                .to_string()
                .contains("missing")
        );

        let unknown = text.replace(
            "omv_enabled = true\n",
            "omv_enabled = true\nspeling_error = true\n",
        );
        assert!(
            parse_preset(&unknown)
                .unwrap_err()
                .to_string()
                .contains("unknown")
        );

        let future = text.replace("config_schema_version = 1", "config_schema_version = 999");
        assert!(
            parse_preset(&future)
                .unwrap_err()
                .to_string()
                .contains("newer")
        );
    }

    #[test]
    fn schema_one_motion_blur_strength_round_trips_as_inert_compatibility_data() {
        let mut changed = builtin_text().parse::<toml::Value>().unwrap();
        changed["settings"]["embedded_effects"]["motion_blur"]["first_person_strength"] =
            toml::Value::Float(0.9);
        let parsed = parse_preset(&toml::to_string(&changed).unwrap())
            .expect("schema-one motion-blur preset");
        assert_eq!(
            parsed
                .settings
                .embedded_effects
                .motion_blur
                .first_person_strength,
            0.9
        );
        let canonical = parsed
            .canonical_text()
            .unwrap()
            .parse::<toml::Value>()
            .unwrap();
        assert_eq!(
            canonical["settings"]["embedded_effects"]["motion_blur"]["first_person_strength"]
                .as_float()
                .map(|value| value as f32),
            Some(0.9)
        );
    }

    #[test]
    fn non_finite_values_are_rejected_before_runtime_application() {
        let text = builtin_text();
        let poisoned = text.replacen(
            "object_roughness_scale = ",
            "object_roughness_scale = nan # ",
            1,
        );
        assert!(
            parse_preset(&poisoned)
                .unwrap_err()
                .to_string()
                .contains("finite")
        );
    }

    #[test]
    fn finite_values_outside_the_public_runtime_range_are_rejected() {
        let text = builtin_text();
        let mut poisoned = text.parse::<toml::Value>().unwrap();
        poisoned["settings"]["native_pbr"]["object_roughness_scale"] = toml::Value::Float(999.0);
        let poisoned = toml::to_string(&poisoned).unwrap();
        let error = parse_preset(&poisoned).unwrap_err().to_string();
        assert!(error.contains("out of range"), "{error}");

        let mut poisoned = text.parse::<toml::Value>().unwrap();
        poisoned["settings"]["embedded_effects"]["temporal_aa"]["history_weight"] =
            toml::Value::Float(-10.0);
        let poisoned = toml::to_string(&poisoned).unwrap();
        let error = parse_preset(&poisoned).unwrap_err().to_string();
        assert!(error.contains("out of range"), "{error}");
    }

    #[test]
    fn semantic_versions_are_strict_and_independent_from_schema_versions() {
        for accepted in ["0.0.0", "1.2.3", "1.2.3-beta.1", "1.2.3+fnv"] {
            validate_semver(accepted).unwrap();
        }
        for rejected in ["1", "1.2", "01.2.3", "1.2.3-", "1.2.3+"] {
            assert!(validate_semver(rejected).is_err(), "{rejected}");
        }
    }

    #[test]
    fn updated_preset_version_preserves_family_and_captures_current_payload() {
        let source = builtin_default_preset().unwrap();
        let mut menu = GraphicsMenuConfig::default();
        menu.screen_space_shaders = false;
        let mut luts = LutCatalog::default();
        luts.assets = crate::luts::shipped_luts_for_test()
            .into_iter()
            .map(std::sync::Arc::new)
            .collect();

        let source_path = Path::new(PRESET_DIRECTORY).join("mojave-cinema.omvpreset.toml");
        let (updated, target) = PresetPublishRequest::capture_new_version(
            &source,
            &source_path,
            42,
            "1.1.0",
            &menu,
            &[],
            &luts,
        )
        .unwrap()
        .into_parts();

        assert_eq!(updated.metadata.id, source.metadata.id);
        assert_eq!(updated.metadata.name, source.metadata.name);
        assert_eq!(updated.metadata.version, "1.1.0");
        assert_ne!(
            updated.payload_revision().unwrap(),
            source.payload_revision().unwrap()
        );
        match target {
            PresetPublishTarget::Update {
                path,
                source_key,
                expected_content_hash,
            } => {
                assert_eq!(path, source_path);
                assert_eq!(source_key, source.key());
                assert_eq!(expected_content_hash, 42);
            }
            PresetPublishTarget::New => panic!("version update must keep its source path"),
        }
    }

    #[test]
    fn updated_preset_version_must_advance_semantic_precedence() {
        assert!(validate_newer_version("1.2.3", "1.2.4").is_ok());
        assert!(validate_newer_version("1.2.3", "2.0.0-beta.1").is_ok());
        assert!(validate_newer_version("1.2.3", "1.2.3").is_err());
        assert!(validate_newer_version("1.2.3", "1.2.3+repacked").is_err());
        assert!(validate_newer_version("1.2.3", "1.2.2").is_err());
        assert_eq!(suggest_next_patch_version("1.2.3"), "1.2.4");
        assert_eq!(suggest_next_patch_version("not-semver"), "1.0.0");
    }

    #[test]
    fn publication_never_deletes_or_renames_a_preset_path() {
        let source = include_str!("presets.rs");
        let publication = source
            .split_once("fn publish_user_preset(")
            .expect("publication function")
            .1
            .split_once("\nfn validate_update_target(")
            .expect("publication function end")
            .0;

        assert!(publication.contains("atomic_create_text"));
        assert!(publication.contains("atomic_write_text"));
        assert!(!publication.contains("remove_file"));
        assert!(!publication.contains("rename("));
    }

    #[test]
    fn duplicate_identity_conflicts_never_choose_a_load_order_winner() {
        let first = builtin_default_preset().unwrap();
        let mut second = first.clone();
        second.metadata.name = "Conflicting default".to_owned();
        let mut entries = vec![
            valid_catalog_entry(first, None, true, 1),
            valid_catalog_entry(second, None, false, 2),
        ];
        mark_duplicate_conflicts(&mut entries);
        assert!(entries.iter().all(|entry| entry.document.is_none()));
        assert!(entries.iter().all(|entry| entry.error.is_some()));
    }

    #[test]
    fn identical_duplicate_is_not_activated_twice() {
        let first = builtin_default_preset().unwrap();
        let second = first.clone();
        let mut entries = vec![
            valid_catalog_entry(first, None, true, 7),
            valid_catalog_entry(second, None, false, 7),
        ];
        mark_duplicate_conflicts(&mut entries);
        assert!(entries[0].document.is_some());
        assert!(entries[1].document.is_none());
    }

    #[test]
    fn local_controls_survive_visual_preset_application() {
        let preset = builtin_default_preset().unwrap();
        let mut menu = GraphicsMenuConfig::default();
        menu.depth_provider = crate::config::DepthProviderConfig::DepthResolve;
        menu.menu_toggle_key = 0x41;
        menu.shader_scan_interval_ms = 777;
        menu.debug_log = true;
        menu.native_pbr.debug_log_draws = true;
        let mut sources = Vec::new();
        let lut_text = include_str!("../luts/01_mojave_natural.cube");
        let mut catalog = LutCatalog::default();
        let shipped = crate::luts::shipped_luts_for_test();
        catalog.assets = shipped.into_iter().map(std::sync::Arc::new).collect();
        preset.apply(&mut menu, &mut sources, &catalog).unwrap();
        assert!(preset.matches_current(&menu, &sources, &catalog).unwrap());
        assert_eq!(menu.menu_toggle_key, 0x41);
        assert_eq!(
            menu.depth_provider,
            crate::config::DepthProviderConfig::DepthResolve
        );
        assert_eq!(menu.shader_scan_interval_ms, 777);
        assert!(menu.debug_log);
        assert!(menu.native_pbr.debug_log_draws);
        assert_eq!(
            preset.dependencies.lut.as_ref().unwrap().revision,
            format!("{:016x}", fingerprint(lut_text.as_bytes()))
        );
    }

    #[test]
    fn active_state_keeps_preset_identity_separate_from_payload_revision() {
        let preset = builtin_default_preset().unwrap();
        let state = PresetActiveState::new(&preset.key(), preset.payload_revision().unwrap());
        let text = toml::to_string(&state).unwrap();
        let decoded: PresetActiveState = toml::from_str(&text).unwrap();
        assert_eq!(decoded.key(), preset.key());
        assert_eq!(
            decoded.payload_revision().unwrap(),
            preset.payload_revision().unwrap()
        );
        assert_eq!(decoded.state_format_version, 1);
    }

    #[test]
    fn missing_dependency_rejects_the_complete_activation_transaction() {
        let preset = builtin_default_preset().unwrap();
        let mut menu = GraphicsMenuConfig::default();
        menu.screen_space_shaders = false;
        let before = toml::Value::try_from(PresetVisualSettingsV1::capture(&menu)).unwrap();
        let mut sources = Vec::new();
        let error = preset
            .apply(&mut menu, &mut sources, &LutCatalog::default())
            .expect_err("missing LUT must reject activation");
        let after = toml::Value::try_from(PresetVisualSettingsV1::capture(&menu)).unwrap();
        assert!(error.to_string().contains("required LUT"));
        assert_eq!(after, before);
        assert!(sources.is_empty());
    }

    #[test]
    fn release_and_installer_preserve_the_user_working_config() {
        let installer = include_str!("../../build_fnv.sh");
        assert!(installer.contains("OMV_DEFAULT_CFGNAME=\"omv.default.toml\""));
        assert!(installer.contains("if [[ ! -f \"$OMV_CFG_PATH\" ]]"));
        assert!(installer.contains("cp \"$OMV_CFG\" \"$OMV_DEFAULT_CFG_PATH\""));

        let packager = include_str!("../../.github/scripts/package_release.sh");
        assert!(packager.contains("OMV_DEFAULT_CONFIG_FILE=\"omv.default.toml\""));
        assert!(!packager.contains("Data/NVSE/plugins/omv/$OMV_CONFIG_FILE"));

        let workflow = include_str!("../../.github/workflows/release.yml");
        assert!(workflow.contains("Data/NVSE/plugins/omv/omv.default.toml"));
        assert!(!workflow.contains("\"Data/NVSE/plugins/omv/omv.toml\""));
    }

    #[test]
    fn slug_never_turns_user_text_into_a_path() {
        assert_eq!(preset_slug("../../My Preset"), "my-preset");
        assert_eq!(preset_slug("  "), "preset");
    }

    #[test]
    fn generated_filename_is_version_free_and_keeps_uuid_inside_the_document() {
        let mut preset = builtin_default_preset().unwrap();
        preset.metadata.name = "Mojave Cinema".to_owned();
        preset.metadata.version = "1.2.3-beta.1".to_owned();
        preset.metadata.id = "35ec76b6-366e-40af-8386-1bd333c9b502".to_owned();
        assert_eq!(
            preset_file_name(&preset.metadata, 0),
            "mojave-cinema.omvpreset.toml"
        );
        assert_eq!(
            preset_file_name(&preset.metadata, 1),
            "mojave-cinema-2.omvpreset.toml"
        );
        assert!(!preset_file_name(&preset.metadata, 0).contains("1.2.3"));
        assert!(!preset_file_name(&preset.metadata, 0).contains("35ec76b6"));
        assert!(
            preset
                .canonical_text()
                .unwrap()
                .contains(&preset.metadata.id)
        );
    }

    #[test]
    fn created_with_metadata_identifies_the_build_without_guessing_a_tag() {
        let provenance = PresetBuildProvenance::current();
        validate_build_provenance(&provenance).unwrap();
        assert_eq!(provenance.omv_version, env!("CARGO_PKG_VERSION"));
        let text = builtin_text();
        assert!(text.contains("[preset.created_with]"));
        assert!(text.contains("git_commit = "));
        assert!(text.contains("git_tag = "));
        assert!(text.contains("git_branch = "));
    }
}

//! Live screen-space shader loading and sidecar configuration.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

use anyhow::{Context, Result};
use libpsycho::os::windows::directx9::{compile_hlsl, dword_aligned_shader_bytecode};
use serde::{Deserialize, Serialize};

use crate::config::{
    BloomingHdrConfig, ContactAoConfig, EmbeddedEffectsConfig, FastAoConfig, SunshaftsConfig,
};

pub(crate) const SHADER_DIR: &str = "./Data/NVSE/plugins/omv/shaders";
const FIRST_OPTION_REGISTER: u32 = 3;
const ENVIRONMENT_REGISTER: u32 = 6;
const SUN_REGISTER: u32 = 8;
const MAX_OPTION_REGISTER: u32 = 31;
const MIN_SHADER_PASSES: u32 = 1;
const MAX_SHADER_PASSES: u32 = 8;
#[derive(Clone, Debug)]
pub(crate) struct ScreenShaderSource {
    pub(crate) kind: ScreenShaderSourceKind,
    pub(crate) name: String,
    pub(crate) path: PathBuf,
    pub(crate) config_path: PathBuf,
    pub(crate) bytecode: Option<Vec<u32>>,
    pub(crate) enabled: bool,
    pub(crate) phase: ShaderPhase,
    pub(crate) pass_count: u32,
    pub(crate) options: Vec<ShaderOption>,
    pub(crate) option_constants: Vec<[f32; 4]>,
    pub(crate) shader_error: Option<String>,
    pub(crate) config_error: Option<String>,
    shader_stamp: FileStamp,
    config_stamp: FileStamp,
}

impl ScreenShaderSource {
    pub(crate) fn is_external_file(&self) -> bool {
        matches!(self.kind, ScreenShaderSourceKind::ExternalFile)
    }

    pub(crate) fn is_embedded_effect(&self) -> bool {
        self.embedded_effect_kind().is_some()
    }

    pub(crate) fn embedded_effect_kind(&self) -> Option<EmbeddedEffectKind> {
        match self.kind {
            ScreenShaderSourceKind::ExternalFile => None,
            ScreenShaderSourceKind::EmbeddedEffect(kind) => Some(kind),
        }
    }

    pub(crate) fn bytecode(&self) -> Option<&[u32]> {
        self.bytecode.as_deref()
    }

    pub(crate) fn set_enabled(&mut self, enabled: bool) -> Result<()> {
        if self.enabled == enabled {
            return Ok(());
        }

        self.enabled = enabled;
        self.save_config()
    }

    pub(crate) fn set_pass_count(&mut self, pass_count: u32) -> Result<()> {
        let pass_count = sanitize_pass_count(pass_count);
        if self.pass_count == pass_count {
            return Ok(());
        }

        self.pass_count = pass_count;
        self.save_config()
    }

    pub(crate) fn phase(&self) -> ShaderPhase {
        self.phase
    }

    pub(crate) fn set_option_float(&mut self, index: usize, value: f32) -> Result<()> {
        let Some(option) = self.options.get_mut(index) else {
            return Ok(());
        };
        let ShaderOptionValue::Float(float) = &mut option.value else {
            return Ok(());
        };

        let value = value.clamp(option.min, option.max);
        if (*float - value).abs() <= f32::EPSILON {
            return Ok(());
        }

        *float = value;
        self.rebuild_option_constants();
        self.save_config()
    }

    pub(crate) fn set_option_integer(&mut self, index: usize, value: i32) -> Result<()> {
        let Some(option) = self.options.get_mut(index) else {
            return Ok(());
        };
        let (min, max) = integer_bounds(option.min, option.max);
        let ShaderOptionValue::Integer(integer) = &mut option.value else {
            return Ok(());
        };

        let value = value.clamp(min, max);
        if *integer == value {
            return Ok(());
        }

        *integer = value;
        self.rebuild_option_constants();
        self.save_config()
    }

    pub(crate) fn set_option_bool(&mut self, index: usize, value: bool) -> Result<()> {
        let Some(option) = self.options.get_mut(index) else {
            return Ok(());
        };
        let ShaderOptionValue::Bool(flag) = &mut option.value else {
            return Ok(());
        };

        if *flag == value {
            return Ok(());
        }

        *flag = value;
        self.rebuild_option_constants();
        self.save_config()
    }

    fn save_config(&mut self) -> Result<()> {
        if self.is_embedded_effect() {
            return Ok(());
        }

        let config = ShaderConfigFile::from_source(self);
        let text = toml::to_string_pretty(&config).context("failed to serialize shader config")?;
        fs::write(&self.config_path, text)
            .with_context(|| format!("failed to write {}", self.config_path.display()))?;
        self.config_stamp = file_stamp(&self.config_path).unwrap_or_default();
        self.config_error = None;
        Ok(())
    }

    fn rebuild_option_constants(&mut self) {
        self.option_constants.clear();

        for option in &self.options {
            let Some(binding) = option.binding else {
                continue;
            };
            let index = (binding.register - FIRST_OPTION_REGISTER) as usize;
            if self.option_constants.len() <= index {
                self.option_constants.resize(index + 1, [0.0; 4]);
            }

            self.option_constants[index][binding.component] = option.value.as_constant();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScreenShaderSourceKind {
    ExternalFile,
    EmbeddedEffect(EmbeddedEffectKind),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EmbeddedEffectKind {
    FastAmbientOcclusion,
    ContactAmbientOcclusion,
    BloomingHdr,
    Sunshafts,
}

#[derive(Clone, Debug)]
pub(crate) struct ShaderOption {
    pub(crate) key: String,
    pub(crate) label: String,
    pub(crate) value: ShaderOptionValue,
    pub(crate) min: f32,
    pub(crate) max: f32,
    binding: Option<ConstantBinding>,
    constant: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) enum ShaderOptionValue {
    Float(f32),
    Integer(i32),
    Bool(bool),
}

impl ShaderOptionValue {
    fn as_constant(&self) -> f32 {
        match self {
            Self::Float(value) => *value,
            Self::Integer(value) => *value as f32,
            Self::Bool(value) => {
                if *value {
                    1.0
                } else {
                    0.0
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ShaderScanResult {
    pub(crate) sources: Vec<ScreenShaderSource>,
    pub(crate) shader_resources_changed: bool,
}

pub(crate) fn scan_screen_shaders(previous: &[ScreenShaderSource]) -> Result<ShaderScanResult> {
    let mut files = shader_files()?;
    files.sort();

    let previous_by_path: HashMap<&Path, &ScreenShaderSource> = previous
        .iter()
        .filter(|source| source.is_external_file())
        .map(|source| (source.path.as_path(), source))
        .collect();

    let mut shader_resources_changed = previous_by_path.len() != files.len();
    let mut sources = Vec::with_capacity(files.len());

    for path in files {
        let previous = previous_by_path.get(path.as_path()).copied();
        let shader_stamp = file_stamp(&path)?;
        let config_path = shader_config_path(&path);
        let config_stamp = ensure_shader_config(&config_path)?;

        let shader_changed = previous
            .is_none_or(|source| source.shader_stamp != shader_stamp || source.path != path);
        let config_changed = previous.is_none_or(|source| source.config_stamp != config_stamp);

        let mut source = if shader_changed {
            shader_resources_changed = true;
            let mut loaded = load_shader_file(&path, previous)
                .unwrap_or_else(|err| failed_shader_source(&path, previous, err));
            loaded.shader_stamp = shader_stamp;
            loaded
        } else {
            match previous {
                Some(source) => source.clone(),
                None => {
                    shader_resources_changed = true;
                    let mut loaded = load_shader_file(&path, None)
                        .unwrap_or_else(|err| failed_shader_source(&path, None, err));
                    loaded.shader_stamp = shader_stamp;
                    loaded
                }
            }
        };

        if config_changed || source.config_path != config_path {
            apply_config(&mut source, &config_path, config_stamp);
        }

        sources.push(source);
    }

    Ok(ShaderScanResult {
        sources,
        shader_resources_changed,
    })
}

pub(crate) fn merge_embedded_sources(
    embedded_config: &EmbeddedEffectsConfig,
    external_sources: Vec<ScreenShaderSource>,
) -> Vec<ScreenShaderSource> {
    let mut sources = embedded_effect_sources(embedded_config);
    sources.extend(external_sources);
    sources.sort_by(|left, right| left.name.cmp(&right.name));
    sources
}

pub(crate) fn sync_embedded_effect_config(
    sources: &[ScreenShaderSource],
    config: &mut EmbeddedEffectsConfig,
) {
    for source in sources {
        match source.embedded_effect_kind() {
            Some(EmbeddedEffectKind::FastAmbientOcclusion) => {
                sync_fast_ao_config(source, &mut config.fast_ao);
            }
            Some(EmbeddedEffectKind::ContactAmbientOcclusion) => {
                sync_contact_ao_config(source, &mut config.contact_ao);
            }
            Some(EmbeddedEffectKind::BloomingHdr) => {
                sync_blooming_hdr_config(source, &mut config.blooming_hdr);
            }
            Some(EmbeddedEffectKind::Sunshafts) => {
                sync_sunshafts_config(source, &mut config.sunshafts);
            }
            None => {}
        }
    }
}

fn embedded_effect_sources(config: &EmbeddedEffectsConfig) -> Vec<ScreenShaderSource> {
    vec![
        fast_ao_source(&config.fast_ao),
        contact_ao_source(&config.contact_ao),
        blooming_hdr_source(&config.blooming_hdr),
        sunshafts_source(&config.sunshafts),
    ]
}

fn fast_ao_source(config: &FastAoConfig) -> ScreenShaderSource {
    embedded_source(
        EmbeddedEffectKind::FastAmbientOcclusion,
        "00_fast_ao",
        config.enabled,
        crate::config::EmbeddedEffectsConfig::phase_for_kind(
            EmbeddedEffectKind::FastAmbientOcclusion,
        ),
        vec![
            float_option("strength", "Strength", config.strength, 0.0, 8.0, 3, 0),
            float_option(
                "radius_scale",
                "Radius scale",
                config.radius_scale,
                8.0,
                260.0,
                3,
                1,
            ),
            float_option(
                "max_radius_pixels",
                "Max radius",
                config.max_radius_pixels,
                1.0,
                48.0,
                3,
                2,
            ),
            float_option(
                "range_scale",
                "Range scale",
                config.range_scale,
                0.006,
                0.2,
                3,
                3,
            ),
            bool_option("debug_depth", "Debug depth view", config.debug_depth, 4, 0),
            bool_option(
                "depth_reversed",
                "Reversed depth",
                config.depth_reversed,
                4,
                1,
            ),
            float_option(
                "min_ambient",
                "Min ambient",
                config.min_ambient,
                0.05,
                0.75,
                4,
                2,
            ),
            float_option(
                "luminance_protection",
                "Luma protect",
                config.luminance_protection,
                0.0,
                1.0,
                4,
                3,
            ),
            float_option("stability", "Stability", config.stability, 0.0, 1.0, 5, 0),
            float_option(
                "first_person_mask",
                "1P mask",
                config.first_person_mask,
                0.0,
                1.0,
                5,
                1,
            ),
            float_option("fog_fade", "Fog fade", config.fog_fade, 0.0, 1.0, 5, 2),
        ],
    )
}

fn contact_ao_source(config: &ContactAoConfig) -> ScreenShaderSource {
    embedded_source(
        EmbeddedEffectKind::ContactAmbientOcclusion,
        "02_contact_ao",
        config.enabled,
        crate::config::EmbeddedEffectsConfig::phase_for_kind(
            EmbeddedEffectKind::ContactAmbientOcclusion,
        ),
        vec![
            float_option("strength", "Strength", config.strength, 0.0, 5.0, 3, 0),
            float_option(
                "radius_pixels",
                "Radius px",
                config.radius_pixels,
                1.0,
                14.0,
                3,
                1,
            ),
            float_option(
                "range_scale",
                "Range scale",
                config.range_scale,
                0.003,
                0.08,
                3,
                2,
            ),
            float_option(
                "bias_scale",
                "Bias scale",
                config.bias_scale,
                0.0,
                0.001,
                3,
                3,
            ),
            bool_option(
                "depth_reversed",
                "Reversed depth",
                config.depth_reversed,
                4,
                1,
            ),
            float_option(
                "min_ambient",
                "Min ambient",
                config.min_ambient,
                0.2,
                0.95,
                4,
                2,
            ),
            float_option("stability", "Stability", config.stability, 0.0, 1.0, 4, 3),
            float_option(
                "first_person_mask",
                "1P mask",
                config.first_person_mask,
                0.0,
                1.0,
                5,
                0,
            ),
            float_option("fog_fade", "Fog fade", config.fog_fade, 0.0, 1.0, 5, 1),
        ],
    )
}

fn blooming_hdr_source(config: &BloomingHdrConfig) -> ScreenShaderSource {
    embedded_source(
        EmbeddedEffectKind::BloomingHdr,
        "07_blooming_hdr_lite",
        config.enabled,
        crate::config::EmbeddedEffectsConfig::phase_for_kind(EmbeddedEffectKind::BloomingHdr),
        vec![
            float_option(
                "bloom_intensity",
                "Bloom intensity",
                config.bloom_intensity,
                0.0,
                1.5,
                3,
                0,
            ),
            float_option(
                "bright_threshold",
                "Bright threshold",
                config.bright_threshold,
                0.25,
                0.95,
                3,
                1,
            ),
            float_option(
                "radius_pixels",
                "Radius px",
                config.radius_pixels,
                0.5,
                7.0,
                3,
                2,
            ),
            float_option("soft_knee", "Soft knee", config.soft_knee, 0.02, 0.65, 3, 3),
            float_option(
                "exposure_bias",
                "Exposure",
                config.exposure_bias,
                -0.5,
                0.5,
                4,
                0,
            ),
            float_option(
                "highlight_shoulder",
                "Highlight rolloff",
                config.highlight_shoulder,
                0.0,
                1.0,
                4,
                1,
            ),
            float_option(
                "saturation",
                "Saturation",
                config.saturation,
                0.0,
                1.5,
                4,
                2,
            ),
            float_option("warmth", "Warmth", config.warmth, -1.0, 1.0, 4, 3),
            float_option(
                "shadow_lift",
                "Shadow lift",
                config.shadow_lift,
                0.0,
                1.0,
                5,
                0,
            ),
            float_option("dither", "Dither", config.dither, 0.0, 1.0, 5, 1),
            bool_option("debug_bloom", "Debug bloom", config.debug_bloom, 5, 2),
            float_option(
                "atmosphere",
                "Atmosphere",
                config.atmosphere,
                0.0,
                1.0,
                5,
                3,
            ),
        ],
    )
}

fn sunshafts_source(config: &SunshaftsConfig) -> ScreenShaderSource {
    embedded_source(
        EmbeddedEffectKind::Sunshafts,
        "09_sunshafts_lite",
        config.enabled,
        crate::config::EmbeddedEffectsConfig::phase_for_kind(EmbeddedEffectKind::Sunshafts),
        vec![
            float_option("intensity", "Intensity", config.intensity, 0.0, 2.5, 3, 0),
            float_option("exposure", "Exposure", config.exposure, 0.0, 2.8, 3, 1),
            float_option("decay", "Decay", config.decay, 0.65, 1.035, 3, 2),
            float_option("density", "Density", config.density, 0.20, 1.35, 3, 3),
            float_option("force", "Force", config.force, 0.0, 4.0, 4, 0),
            float_option(
                "bright_threshold",
                "Bright threshold",
                config.bright_threshold,
                0.28,
                0.95,
                4,
                2,
            ),
            float_option("warmth", "Warmth", config.warmth, 0.0, 1.0, 4, 3),
            float_option(
                "first_person_occlusion",
                "1P occlusion",
                config.first_person_occlusion,
                0.0,
                1.0,
                5,
                0,
            ),
            float_option(
                "sun_falloff",
                "Sun falloff",
                config.sun_falloff,
                0.16,
                1.20,
                5,
                1,
            ),
            bool_option(
                "depth_reversed",
                "Reversed depth",
                config.depth_reversed,
                5,
                2,
            ),
            bool_option("debug_mask", "Debug mask", config.debug_mask, 5, 3),
            integer_option(
                "sun_sample_px",
                "Sun sample px",
                config.sun_sample_px,
                2,
                48,
                7,
                0,
            ),
            float_option(
                "glare_radius",
                "Glare radius",
                config.glare_radius,
                0.010,
                0.080,
                7,
                1,
            ),
            float_option(
                "occlusion_softness",
                "Occlusion softness",
                config.occlusion_softness,
                0.0,
                0.75,
                7,
                3,
            ),
        ],
    )
}

fn embedded_source(
    kind: EmbeddedEffectKind,
    name: &str,
    enabled: bool,
    phase: ShaderPhase,
    options: Vec<ShaderOption>,
) -> ScreenShaderSource {
    let mut source = ScreenShaderSource {
        kind: ScreenShaderSourceKind::EmbeddedEffect(kind),
        name: name.to_owned(),
        path: PathBuf::from("<embedded>"),
        config_path: PathBuf::from(crate::config::CONFIG_PATH),
        bytecode: None,
        enabled,
        phase,
        pass_count: MIN_SHADER_PASSES,
        options,
        option_constants: Vec::new(),
        shader_error: None,
        config_error: None,
        shader_stamp: FileStamp::default(),
        config_stamp: FileStamp::default(),
    };
    source.rebuild_option_constants();
    source
}

fn float_option(
    key: &str,
    label: &str,
    value: f32,
    min: f32,
    max: f32,
    register: u32,
    component: usize,
) -> ShaderOption {
    option(
        key,
        label,
        ShaderOptionValue::Float(value),
        min,
        max,
        register,
        component,
    )
}

fn integer_option(
    key: &str,
    label: &str,
    value: i32,
    min: i32,
    max: i32,
    register: u32,
    component: usize,
) -> ShaderOption {
    option(
        key,
        label,
        ShaderOptionValue::Integer(value),
        min as f32,
        max as f32,
        register,
        component,
    )
}

fn bool_option(
    key: &str,
    label: &str,
    value: bool,
    register: u32,
    component: usize,
) -> ShaderOption {
    option(
        key,
        label,
        ShaderOptionValue::Bool(value),
        0.0,
        1.0,
        register,
        component,
    )
}

fn option(
    key: &str,
    label: &str,
    value: ShaderOptionValue,
    min: f32,
    max: f32,
    register: u32,
    component: usize,
) -> ShaderOption {
    ShaderOption {
        key: key.to_owned(),
        label: label.to_owned(),
        value,
        min,
        max,
        binding: Some(ConstantBinding {
            register,
            component,
        }),
        constant: Some(format!("c{}.{}", register, component_name(component))),
    }
}

fn sync_fast_ao_config(source: &ScreenShaderSource, config: &mut FastAoConfig) {
    config.enabled = source.enabled;
    for option in &source.options {
        match option.key.as_str() {
            "strength" => config.strength = option_float(option),
            "radius_scale" => config.radius_scale = option_float(option),
            "max_radius_pixels" => config.max_radius_pixels = option_float(option),
            "range_scale" => config.range_scale = option_float(option),
            "debug_depth" => config.debug_depth = option_bool(option),
            "depth_reversed" => config.depth_reversed = option_bool(option),
            "min_ambient" => config.min_ambient = option_float(option),
            "luminance_protection" => config.luminance_protection = option_float(option),
            "stability" => config.stability = option_float(option),
            "first_person_mask" => config.first_person_mask = option_float(option),
            "fog_fade" => config.fog_fade = option_float(option),
            _ => {}
        }
    }
}

fn sync_contact_ao_config(source: &ScreenShaderSource, config: &mut ContactAoConfig) {
    config.enabled = source.enabled;
    for option in &source.options {
        match option.key.as_str() {
            "strength" => config.strength = option_float(option),
            "radius_pixels" => config.radius_pixels = option_float(option),
            "range_scale" => config.range_scale = option_float(option),
            "bias_scale" => config.bias_scale = option_float(option),
            "depth_reversed" => config.depth_reversed = option_bool(option),
            "min_ambient" => config.min_ambient = option_float(option),
            "stability" => config.stability = option_float(option),
            "first_person_mask" => config.first_person_mask = option_float(option),
            "fog_fade" => config.fog_fade = option_float(option),
            _ => {}
        }
    }
}

fn sync_blooming_hdr_config(source: &ScreenShaderSource, config: &mut BloomingHdrConfig) {
    config.enabled = source.enabled;
    for option in &source.options {
        match option.key.as_str() {
            "bloom_intensity" => config.bloom_intensity = option_float(option),
            "bright_threshold" => config.bright_threshold = option_float(option),
            "radius_pixels" => config.radius_pixels = option_float(option),
            "soft_knee" => config.soft_knee = option_float(option),
            "exposure_bias" => config.exposure_bias = option_float(option),
            "highlight_shoulder" => config.highlight_shoulder = option_float(option),
            "saturation" => config.saturation = option_float(option),
            "warmth" => config.warmth = option_float(option),
            "shadow_lift" => config.shadow_lift = option_float(option),
            "dither" => config.dither = option_float(option),
            "debug_bloom" => config.debug_bloom = option_bool(option),
            "atmosphere" => config.atmosphere = option_float(option),
            _ => {}
        }
    }
}

fn sync_sunshafts_config(source: &ScreenShaderSource, config: &mut SunshaftsConfig) {
    config.enabled = source.enabled;
    for option in &source.options {
        match option.key.as_str() {
            "intensity" => config.intensity = option_float(option),
            "exposure" => config.exposure = option_float(option),
            "decay" => config.decay = option_float(option),
            "density" => config.density = option_float(option),
            "force" => config.force = option_float(option),
            "bright_threshold" => config.bright_threshold = option_float(option),
            "warmth" => config.warmth = option_float(option),
            "first_person_occlusion" => config.first_person_occlusion = option_float(option),
            "sun_falloff" => config.sun_falloff = option_float(option),
            "depth_reversed" => config.depth_reversed = option_bool(option),
            "debug_mask" => config.debug_mask = option_bool(option),
            "sun_sample_px" => config.sun_sample_px = option_integer(option),
            "glare_radius" => config.glare_radius = option_float(option),
            "occlusion_softness" => config.occlusion_softness = option_float(option),
            _ => {}
        }
    }
}

fn option_float(option: &ShaderOption) -> f32 {
    match option.value {
        ShaderOptionValue::Float(value) => value,
        ShaderOptionValue::Integer(value) => value as f32,
        ShaderOptionValue::Bool(value) => value as u8 as f32,
    }
}

fn option_integer(option: &ShaderOption) -> i32 {
    match option.value {
        ShaderOptionValue::Integer(value) => value,
        ShaderOptionValue::Float(value) => value.round() as i32,
        ShaderOptionValue::Bool(value) => value as i32,
    }
}

fn option_bool(option: &ShaderOption) -> bool {
    match option.value {
        ShaderOptionValue::Bool(value) => value,
        ShaderOptionValue::Float(value) => value > 0.5,
        ShaderOptionValue::Integer(value) => value != 0,
    }
}

fn shader_files() -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    let path = Path::new(SHADER_DIR);
    if !path.exists() {
        return Ok(files);
    }

    let entries = fs::read_dir(path)
        .with_context(|| format!("failed to read shader directory {}", path.display()))?;

    for entry in entries {
        let entry = entry.with_context(|| format!("failed to read entry in {}", path.display()))?;
        let path = entry.path();
        if path.is_file() && is_shader_file(&path) {
            files.push(path);
        }
    }

    Ok(files)
}

fn is_shader_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            ext.eq_ignore_ascii_case("pso")
                || ext.eq_ignore_ascii_case("cso")
                || ext.eq_ignore_ascii_case("hlsl")
        })
}

fn shader_config_path(path: &Path) -> PathBuf {
    path.with_extension("toml")
}

fn ensure_shader_config(path: &Path) -> Result<FileStamp> {
    if path.exists() {
        return file_stamp(path);
    }

    let config = ShaderConfigFile::default();
    let text =
        toml::to_string_pretty(&config).context("failed to serialize default shader config")?;
    fs::write(path, text).with_context(|| format!("failed to create {}", path.display()))?;
    log::info!(
        "[SHADERS] Created default shader config '{}'",
        path.display()
    );
    file_stamp(path)
}

fn load_shader_file(
    path: &Path,
    previous: Option<&ScreenShaderSource>,
) -> Result<ScreenShaderSource> {
    let bytecode = if path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("hlsl"))
    {
        compile_hlsl_shader(path)?
    } else {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read shader file {}", path.display()))?;
        dword_aligned_shader_bytecode(&bytes)?
    };

    log::info!("[SHADERS] Loaded shader '{}'", path.display());

    Ok(ScreenShaderSource {
        kind: ScreenShaderSourceKind::ExternalFile,
        name: shader_name(path),
        path: path.to_owned(),
        config_path: shader_config_path(path),
        bytecode: Some(bytecode),
        enabled: previous.map_or(true, |source| source.enabled),
        phase: previous.map_or(ShaderPhase::default(), |source| source.phase),
        pass_count: previous.map_or(MIN_SHADER_PASSES, |source| source.pass_count),
        options: previous.map_or_else(Vec::new, |source| source.options.clone()),
        option_constants: previous.map_or_else(Vec::new, |source| source.option_constants.clone()),
        shader_error: None,
        config_error: previous.and_then(|source| source.config_error.clone()),
        shader_stamp: FileStamp::default(),
        config_stamp: previous.map_or_else(FileStamp::default, |source| source.config_stamp),
    })
}

fn failed_shader_source(
    path: &Path,
    previous: Option<&ScreenShaderSource>,
    err: anyhow::Error,
) -> ScreenShaderSource {
    let message = format!("{err:#}");
    log::warn!("[SHADERS] Failed to load {}: {message}", path.display());

    if let Some(previous) = previous {
        let mut source = previous.clone();
        source.shader_error = Some(message);
        return source;
    }

    ScreenShaderSource {
        kind: ScreenShaderSourceKind::ExternalFile,
        name: shader_name(path),
        path: path.to_owned(),
        config_path: shader_config_path(path),
        bytecode: None,
        enabled: true,
        phase: previous.map_or(ShaderPhase::default(), |source| source.phase),
        pass_count: MIN_SHADER_PASSES,
        options: Vec::new(),
        option_constants: Vec::new(),
        shader_error: Some(message),
        config_error: None,
        shader_stamp: FileStamp::default(),
        config_stamp: FileStamp::default(),
    }
}

fn apply_config(source: &mut ScreenShaderSource, config_path: &Path, config_stamp: FileStamp) {
    source.config_path = config_path.to_owned();
    source.config_stamp = config_stamp;

    match load_shader_config(config_path) {
        Ok(config) => {
            source.enabled = config.shader.enabled;
            source.phase = config.shader.phase;
            source.pass_count = sanitize_pass_count(config.shader.passes);
            source.options = config.options.into_iter().map(ShaderOption::from).collect();
            assign_missing_bindings(&mut source.options);
            source.rebuild_option_constants();
            source.config_error = None;
            log::debug!("[SHADERS] Loaded shader config '{}'", config_path.display());
        }
        Err(err) => {
            let message = format!("{err:#}");
            source.config_error = Some(message.clone());
            log::warn!(
                "[SHADERS] Failed to load shader config {}: {message}",
                config_path.display()
            );
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ShaderPhase {
    ScenePreImageSpace,
    ScenePostImageSpace,
    #[default]
    FinalImageSpace,
}

impl ShaderPhase {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::ScenePreImageSpace => "scene_pre_image_space",
            Self::ScenePostImageSpace => "scene_post_image_space",
            Self::FinalImageSpace => "final_image_space",
        }
    }
}

fn sanitize_pass_count(pass_count: u32) -> u32 {
    pass_count.clamp(MIN_SHADER_PASSES, MAX_SHADER_PASSES)
}

fn load_shader_config(path: &Path) -> Result<ShaderConfigFile> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read shader config {}", path.display()))?;
    toml::from_str(&text)
        .with_context(|| format!("failed to parse shader config {}", path.display()))
}

fn assign_missing_bindings(options: &mut [ShaderOption]) {
    let mut next_register = FIRST_OPTION_REGISTER;
    let mut next_component = 0usize;

    for option in options {
        if option.binding.is_none() {
            option.binding = Some(ConstantBinding {
                register: next_register,
                component: next_component,
            });
            option.constant = Some(format!(
                "c{}.{}",
                next_register,
                component_name(next_component)
            ));
        }

        next_component += 1;
        if next_component == 4 {
            next_component = 0;
            next_register = next_option_register(next_register);
        }
    }
}

fn next_option_register(register: u32) -> u32 {
    let mut next = register + 1;
    while is_reserved_register(next) {
        next += 1;
    }
    next
}

fn is_reserved_register(register: u32) -> bool {
    register == ENVIRONMENT_REGISTER || register == SUN_REGISTER
}

fn compile_hlsl_shader(path: &Path) -> Result<Vec<u32>> {
    let source = fs::read(path)
        .with_context(|| format!("failed to read shader source {}", path.display()))?;
    let source_name = path.to_string_lossy();
    let bytecode = compile_hlsl_bytes(&source_name, &source, "ps_3_0")?;
    log::info!("[SHADERS] Compiled HLSL shader '{}'", path.display());
    Ok(bytecode)
}

pub(crate) fn compile_hlsl_source(source_name: &str, source: &[u8]) -> Result<Vec<u32>> {
    compile_hlsl_source_target(source_name, source, "ps_3_0")
}

pub(crate) fn compile_hlsl_source_target(
    source_name: &str,
    source: &[u8],
    target: &str,
) -> Result<Vec<u32>> {
    compile_hlsl_bytes(source_name, source, target)
}

fn compile_hlsl_bytes(source_name: &str, source: &[u8], target: &str) -> Result<Vec<u32>> {
    compile_hlsl(source_name, source, target).map_err(Into::into)
}

fn shader_name(path: &Path) -> String {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("unnamed")
        .to_owned()
}

fn file_stamp(path: &Path) -> Result<FileStamp> {
    let metadata =
        fs::metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    Ok(FileStamp {
        len: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FileStamp {
    len: u64,
    modified: Option<SystemTime>,
}

#[derive(Clone, Copy, Debug)]
struct ConstantBinding {
    register: u32,
    component: usize,
}

impl ConstantBinding {
    fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let rest = text.strip_prefix('c')?;
        let (register, component) = rest.split_once('.')?;
        let register = register.parse::<u32>().ok()?;
        if !(FIRST_OPTION_REGISTER..=MAX_OPTION_REGISTER).contains(&register)
            || is_reserved_register(register)
        {
            return None;
        }

        let component = match component {
            "x" | "X" => 0,
            "y" | "Y" => 1,
            "z" | "Z" => 2,
            "w" | "W" => 3,
            _ => return None,
        };

        Some(Self {
            register,
            component,
        })
    }
}

fn component_name(component: usize) -> &'static str {
    match component {
        0 => "x",
        1 => "y",
        2 => "z",
        3 => "w",
        _ => "x",
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
struct ShaderConfigFile {
    shader: ShaderConfigHeader,
    options: Vec<ShaderOptionConfig>,
}

impl Default for ShaderConfigFile {
    fn default() -> Self {
        Self {
            shader: ShaderConfigHeader::default(),
            options: Vec::new(),
        }
    }
}

impl ShaderConfigFile {
    fn from_source(source: &ScreenShaderSource) -> Self {
        Self {
            shader: ShaderConfigHeader {
                enabled: source.enabled,
                phase: source.phase,
                passes: source.pass_count,
            },
            options: source
                .options
                .iter()
                .map(ShaderOptionConfig::from_option)
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
struct ShaderConfigHeader {
    enabled: bool,
    phase: ShaderPhase,
    passes: u32,
}

impl Default for ShaderConfigHeader {
    fn default() -> Self {
        Self {
            enabled: true,
            phase: ShaderPhase::default(),
            passes: MIN_SHADER_PASSES,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
struct ShaderOptionConfig {
    key: String,
    label: String,
    kind: ShaderOptionKind,
    value: ShaderOptionConfigValue,
    min: f32,
    max: f32,
    constant: Option<String>,
}

impl Default for ShaderOptionConfig {
    fn default() -> Self {
        Self {
            key: String::new(),
            label: String::new(),
            kind: ShaderOptionKind::Float,
            value: ShaderOptionConfigValue::Float(0.0),
            min: 0.0,
            max: 1.0,
            constant: None,
        }
    }
}

impl ShaderOptionConfig {
    fn from_option(option: &ShaderOption) -> Self {
        let (kind, value) = match option.value {
            ShaderOptionValue::Float(value) => (
                ShaderOptionKind::Float,
                ShaderOptionConfigValue::Float(value),
            ),
            ShaderOptionValue::Integer(value) => (
                ShaderOptionKind::Integer,
                ShaderOptionConfigValue::Integer(value as i64),
            ),
            ShaderOptionValue::Bool(value) => {
                (ShaderOptionKind::Bool, ShaderOptionConfigValue::Bool(value))
            }
        };

        Self {
            key: option.key.clone(),
            label: option.label.clone(),
            kind,
            value,
            min: option.min,
            max: option.max,
            constant: option.constant.clone(),
        }
    }
}

impl From<ShaderOptionConfig> for ShaderOption {
    fn from(config: ShaderOptionConfig) -> Self {
        let key = if config.key.is_empty() {
            "option".to_owned()
        } else {
            config.key
        };
        let label = if config.label.is_empty() {
            key.clone()
        } else {
            config.label
        };

        let (min, max) = sanitize_float_bounds(config.min, config.max);
        let value = match config.kind {
            ShaderOptionKind::Float => {
                ShaderOptionValue::Float(sanitize_float_value(config.value.as_float(), min, max))
            }
            ShaderOptionKind::Integer => ShaderOptionValue::Integer(sanitize_integer_value(
                config.value.as_integer(),
                min,
                max,
            )),
            ShaderOptionKind::Bool => ShaderOptionValue::Bool(config.value.as_bool()),
        };
        let binding = config.constant.as_deref().and_then(ConstantBinding::parse);

        Self {
            key,
            label,
            value,
            min,
            max,
            binding,
            constant: config.constant,
        }
    }
}

fn sanitize_float_bounds(min: f32, max: f32) -> (f32, f32) {
    let min = if min.is_finite() { min } else { 0.0 };
    let max = if max.is_finite() { max } else { min.max(1.0) };
    if min <= max { (min, max) } else { (max, min) }
}

fn sanitize_float_value(value: f32, min: f32, max: f32) -> f32 {
    if value.is_finite() {
        value.clamp(min, max)
    } else {
        min
    }
}

fn sanitize_integer_value(value: i32, min: f32, max: f32) -> i32 {
    let (min, max) = integer_bounds(min, max);
    value.clamp(min, max)
}

fn integer_bounds(min: f32, max: f32) -> (i32, i32) {
    let (min, max) = sanitize_float_bounds(min, max);
    let min = finite_i32(min.round());
    let max = finite_i32(max.round());
    if min <= max { (min, max) } else { (max, min) }
}

fn finite_i32(value: f32) -> i32 {
    if !value.is_finite() {
        return 0;
    }

    value.clamp(i32::MIN as f32, i32::MAX as f32) as i32
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ShaderOptionKind {
    Float,
    Integer,
    Bool,
}

impl Default for ShaderOptionKind {
    fn default() -> Self {
        Self::Float
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum ShaderOptionConfigValue {
    Float(f32),
    Bool(bool),
    Integer(i64),
}

impl Default for ShaderOptionConfigValue {
    fn default() -> Self {
        Self::Float(0.0)
    }
}

impl ShaderOptionConfigValue {
    fn as_float(self) -> f32 {
        match self {
            Self::Float(value) => value,
            Self::Bool(value) => {
                if value {
                    1.0
                } else {
                    0.0
                }
            }
            Self::Integer(value) => value as f32,
        }
    }

    fn as_integer(self) -> i32 {
        match self {
            Self::Float(value) => finite_i32(value.round()),
            Self::Bool(value) => {
                if value {
                    1
                } else {
                    0
                }
            }
            Self::Integer(value) => value.clamp(i32::MIN as i64, i32::MAX as i64) as i32,
        }
    }

    fn as_bool(self) -> bool {
        match self {
            Self::Float(value) => value != 0.0,
            Self::Bool(value) => value,
            Self::Integer(value) => value != 0,
        }
    }
}

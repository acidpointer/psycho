//! Graphics module configuration.

use std::sync::OnceLock;
use std::{fs, path::Path};

use anyhow::{Context, Result};
use libpsycho::config::Config;
use serde::{Deserialize, Serialize};
use toml_edit::{DocumentMut, value};

use crate::shaders::ShaderPhase;

pub(crate) const CONFIG_PATH: &str = "Data/NVSE/plugins/omv/omv.toml";

static CONFIG: OnceLock<PsychoGraphicsConfig> = OnceLock::new();

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct PsychoGraphicsConfig {
    pub(crate) graphics: GraphicsConfig,
    pub(crate) diagnostics: DiagnosticsConfig,
}

impl Default for PsychoGraphicsConfig {
    fn default() -> Self {
        Self {
            graphics: GraphicsConfig::default(),
            diagnostics: DiagnosticsConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct GraphicsConfig {
    pub(crate) screen_space_shaders: bool,
    pub(crate) native_pbr: NativePbrConfig,
    pub(crate) embedded_effects: EmbeddedEffectsConfig,
    pub(crate) depth_provider: DepthProviderConfig,
    pub(crate) menu_toggle_key: u32,
    pub(crate) shader_scan_interval_ms: u64,
}

impl Default for GraphicsConfig {
    fn default() -> Self {
        Self {
            screen_space_shaders: true,
            native_pbr: NativePbrConfig::default(),
            embedded_effects: EmbeddedEffectsConfig::default(),
            depth_provider: DepthProviderConfig::default(),
            menu_toggle_key: 0x2D,
            shader_scan_interval_ms: 200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct NativePbrConfig {
    pub(crate) enabled: bool,
    pub(crate) debug_log_draws: bool,
    pub(crate) metallicness: f32,
    pub(crate) roughness_scale: f32,
    pub(crate) light_scale: f32,
    pub(crate) ambient_scale: f32,
    pub(crate) albedo_saturation: f32,
    pub(crate) terrain_lod_noise_scale: f32,
    pub(crate) terrain_lod_noise_tile: f32,
    pub(crate) object_default: NativePbrProfileConfig,
    pub(crate) object_rain: NativePbrProfileConfig,
    pub(crate) object_night: NativePbrProfileConfig,
    pub(crate) object_night_rain: NativePbrProfileConfig,
    pub(crate) object_interior: NativePbrProfileConfig,
    pub(crate) terrain_default: NativePbrProfileConfig,
    pub(crate) terrain_rain: NativePbrProfileConfig,
    pub(crate) terrain_night: NativePbrProfileConfig,
    pub(crate) terrain_night_rain: NativePbrProfileConfig,
}

impl Default for NativePbrConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            debug_log_draws: false,
            metallicness: 0.0,
            roughness_scale: 1.0,
            light_scale: 1.0,
            ambient_scale: 1.0,
            albedo_saturation: 1.0,
            terrain_lod_noise_scale: 1.0,
            terrain_lod_noise_tile: 1.75,
            object_default: NativePbrProfileConfig::default(),
            object_rain: NativePbrProfileConfig::default(),
            object_night: NativePbrProfileConfig::default(),
            object_night_rain: NativePbrProfileConfig::default(),
            object_interior: NativePbrProfileConfig::default(),
            terrain_default: NativePbrProfileConfig::default(),
            terrain_rain: NativePbrProfileConfig::default(),
            terrain_night: NativePbrProfileConfig::default(),
            terrain_night_rain: NativePbrProfileConfig::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct NativePbrProfileConfig {
    pub(crate) metallicness: Option<f32>,
    pub(crate) roughness_scale: Option<f32>,
    pub(crate) light_scale: Option<f32>,
    pub(crate) ambient_scale: Option<f32>,
    pub(crate) albedo_saturation: Option<f32>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct EmbeddedEffectsConfig {
    pub(crate) fast_ao: FastAoConfig,
    pub(crate) contact_ao: ContactAoConfig,
    pub(crate) blooming_hdr: BloomingHdrConfig,
    pub(crate) sunshafts: SunshaftsConfig,
}

impl Default for EmbeddedEffectsConfig {
    fn default() -> Self {
        Self {
            fast_ao: FastAoConfig::default(),
            contact_ao: ContactAoConfig::default(),
            blooming_hdr: BloomingHdrConfig::default(),
            sunshafts: SunshaftsConfig::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct FastAoConfig {
    pub(crate) enabled: bool,
    pub(crate) strength: f32,
    pub(crate) radius_scale: f32,
    pub(crate) max_radius_pixels: f32,
    pub(crate) range_scale: f32,
    pub(crate) debug_depth: bool,
    pub(crate) depth_reversed: bool,
    pub(crate) min_ambient: f32,
    pub(crate) luminance_protection: f32,
    pub(crate) stability: f32,
    pub(crate) first_person_mask: f32,
    pub(crate) fog_fade: f32,
}

impl Default for FastAoConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            strength: 0.73,
            radius_scale: 75.5,
            max_radius_pixels: 7.6,
            range_scale: 0.076,
            debug_depth: false,
            depth_reversed: true,
            min_ambient: 0.18,
            luminance_protection: 0.45,
            stability: 0.65,
            first_person_mask: 1.0,
            fog_fade: 1.0,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct ContactAoConfig {
    pub(crate) enabled: bool,
    pub(crate) strength: f32,
    pub(crate) radius_pixels: f32,
    pub(crate) range_scale: f32,
    pub(crate) bias_scale: f32,
    pub(crate) depth_reversed: bool,
    pub(crate) min_ambient: f32,
    pub(crate) stability: f32,
    pub(crate) first_person_mask: f32,
    pub(crate) fog_fade: f32,
}

impl Default for ContactAoConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            strength: 0.58,
            radius_pixels: 4.3,
            range_scale: 0.031,
            bias_scale: 0.0,
            depth_reversed: true,
            min_ambient: 0.67,
            stability: 0.63,
            first_person_mask: 1.0,
            fog_fade: 1.0,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct BloomingHdrConfig {
    pub(crate) enabled: bool,
    pub(crate) bloom_intensity: f32,
    pub(crate) bright_threshold: f32,
    pub(crate) radius_pixels: f32,
    pub(crate) soft_knee: f32,
    pub(crate) exposure_bias: f32,
    pub(crate) highlight_shoulder: f32,
    pub(crate) saturation: f32,
    pub(crate) warmth: f32,
    pub(crate) shadow_lift: f32,
    pub(crate) dither: f32,
    pub(crate) debug_bloom: bool,
    pub(crate) atmosphere: f32,
}

impl Default for BloomingHdrConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bloom_intensity: 0.444,
            bright_threshold: 0.457,
            radius_pixels: 3.354,
            soft_knee: 0.219,
            exposure_bias: 0.055,
            highlight_shoulder: 0.682,
            saturation: 1.249,
            warmth: 0.543,
            shadow_lift: 0.228,
            dither: 0.459,
            debug_bloom: false,
            atmosphere: 0.38,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct SunshaftsConfig {
    pub(crate) enabled: bool,
    pub(crate) intensity: f32,
    pub(crate) exposure: f32,
    pub(crate) decay: f32,
    pub(crate) density: f32,
    pub(crate) force: f32,
    pub(crate) bright_threshold: f32,
    pub(crate) warmth: f32,
    pub(crate) first_person_occlusion: f32,
    pub(crate) sun_falloff: f32,
    pub(crate) depth_reversed: bool,
    pub(crate) debug_mask: bool,
    pub(crate) sun_sample_px: i32,
    pub(crate) glare_radius: f32,
    pub(crate) occlusion_softness: f32,
}

impl Default for SunshaftsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            intensity: 0.34,
            exposure: 0.52,
            decay: 1.005,
            density: 1.08,
            force: 2.05,
            bright_threshold: 0.56,
            warmth: 0.64,
            first_person_occlusion: 1.0,
            sun_falloff: 1.05,
            depth_reversed: true,
            debug_mask: false,
            sun_sample_px: 32,
            glare_radius: 0.044,
            occlusion_softness: 0.42,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DepthProviderConfig {
    None,
    #[default]
    #[serde(alias = "d3d9_auto")]
    #[serde(alias = "fallout_new_vegas_image_space")]
    #[serde(alias = "fallout_new_vegas_d3d_depth")]
    FalloutNewVegas,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct DiagnosticsConfig {
    pub(crate) debug_log: bool,
}

impl Default for DiagnosticsConfig {
    fn default() -> Self {
        Self { debug_log: false }
    }
}

pub(crate) fn load_config() -> &'static PsychoGraphicsConfig {
    CONFIG.get_or_init(|| Config::load_readonly::<PsychoGraphicsConfig>(CONFIG_PATH))
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct GraphicsMenuConfig {
    pub(crate) screen_space_shaders: bool,
    pub(crate) native_pbr: NativePbrConfig,
    pub(crate) embedded_effects: EmbeddedEffectsConfig,
    pub(crate) depth_provider: DepthProviderConfig,
    pub(crate) menu_toggle_key: u32,
    pub(crate) shader_scan_interval_ms: u64,
    pub(crate) debug_log: bool,
}

impl Default for GraphicsMenuConfig {
    fn default() -> Self {
        let graphics = GraphicsConfig::default();
        let diagnostics = DiagnosticsConfig::default();
        Self {
            screen_space_shaders: graphics.screen_space_shaders,
            native_pbr: graphics.native_pbr,
            embedded_effects: graphics.embedded_effects,
            depth_provider: graphics.depth_provider,
            menu_toggle_key: graphics.menu_toggle_key,
            shader_scan_interval_ms: graphics.shader_scan_interval_ms,
            debug_log: diagnostics.debug_log,
        }
    }
}

impl From<&PsychoGraphicsConfig> for GraphicsMenuConfig {
    fn from(value: &PsychoGraphicsConfig) -> Self {
        Self {
            screen_space_shaders: value.graphics.screen_space_shaders,
            native_pbr: value.graphics.native_pbr,
            embedded_effects: value.graphics.embedded_effects,
            depth_provider: value.graphics.depth_provider,
            menu_toggle_key: value.graphics.menu_toggle_key,
            shader_scan_interval_ms: value.graphics.shader_scan_interval_ms,
            debug_log: value.diagnostics.debug_log,
        }
    }
}

impl DepthProviderConfig {
    pub(crate) fn config_value(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::FalloutNewVegas => "fallout_new_vegas",
        }
    }
}

impl EmbeddedEffectsConfig {
    pub(crate) fn phase_for_kind(kind: crate::shaders::EmbeddedEffectKind) -> ShaderPhase {
        match kind {
            crate::shaders::EmbeddedEffectKind::FastAmbientOcclusion
            | crate::shaders::EmbeddedEffectKind::ContactAmbientOcclusion => {
                ShaderPhase::ScenePreImageSpace
            }
            crate::shaders::EmbeddedEffectKind::BloomingHdr => ShaderPhase::FinalImageSpace,
            crate::shaders::EmbeddedEffectKind::Sunshafts => ShaderPhase::ScenePostImageSpace,
        }
    }
}

pub(crate) fn save_menu_config(config: &GraphicsMenuConfig) -> Result<()> {
    let path = Path::new(CONFIG_PATH);
    let content = fs::read_to_string(path).unwrap_or_default();
    let mut doc = if content.trim().is_empty() {
        DocumentMut::new()
    } else {
        content
            .parse::<DocumentMut>()
            .with_context(|| format!("failed to parse {}", path.display()))?
    };

    doc["graphics"]["screen_space_shaders"] = value(config.screen_space_shaders);
    if let Some(graphics) = doc["graphics"].as_table_mut() {
        graphics.remove("imgui_menu");
    }
    doc["graphics"]["menu_toggle_key"] = value(config.menu_toggle_key as i64);
    doc["graphics"]["shader_scan_interval_ms"] =
        value(config.shader_scan_interval_ms.min(i64::MAX as u64) as i64);
    doc["graphics"]["depth_provider"] = value(config.depth_provider.config_value());
    save_embedded_effect_config(&mut doc, &config.embedded_effects);
    doc["graphics"]["native_pbr"]["enabled"] = value(config.native_pbr.enabled);
    doc["graphics"]["native_pbr"]["debug_log_draws"] = value(config.native_pbr.debug_log_draws);
    doc["graphics"]["native_pbr"]["metallicness"] = value(config.native_pbr.metallicness as f64);
    doc["graphics"]["native_pbr"]["roughness_scale"] =
        value(config.native_pbr.roughness_scale as f64);
    doc["graphics"]["native_pbr"]["light_scale"] = value(config.native_pbr.light_scale as f64);
    doc["graphics"]["native_pbr"]["ambient_scale"] = value(config.native_pbr.ambient_scale as f64);
    doc["graphics"]["native_pbr"]["albedo_saturation"] =
        value(config.native_pbr.albedo_saturation as f64);
    doc["graphics"]["native_pbr"]["terrain_lod_noise_scale"] =
        value(config.native_pbr.terrain_lod_noise_scale as f64);
    doc["graphics"]["native_pbr"]["terrain_lod_noise_tile"] =
        value(config.native_pbr.terrain_lod_noise_tile as f64);
    if let Some(native_pbr) = doc["graphics"]["native_pbr"].as_table_mut() {
        native_pbr.remove("experimental_shader_replacement");
        native_pbr.remove("require_vanilla_prologues");
    }
    doc["diagnostics"]["debug_log"] = value(config.debug_log);

    let updated = doc.to_string();
    if updated == content {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(path, updated).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn save_embedded_effect_config(doc: &mut DocumentMut, config: &EmbeddedEffectsConfig) {
    let fast = &config.fast_ao;
    doc["graphics"]["embedded_effects"]["fast_ao"]["enabled"] = value(fast.enabled);
    doc["graphics"]["embedded_effects"]["fast_ao"]["strength"] = value(fast.strength as f64);
    doc["graphics"]["embedded_effects"]["fast_ao"]["radius_scale"] =
        value(fast.radius_scale as f64);
    doc["graphics"]["embedded_effects"]["fast_ao"]["max_radius_pixels"] =
        value(fast.max_radius_pixels as f64);
    doc["graphics"]["embedded_effects"]["fast_ao"]["range_scale"] = value(fast.range_scale as f64);
    doc["graphics"]["embedded_effects"]["fast_ao"]["debug_depth"] = value(fast.debug_depth);
    doc["graphics"]["embedded_effects"]["fast_ao"]["depth_reversed"] = value(fast.depth_reversed);
    doc["graphics"]["embedded_effects"]["fast_ao"]["min_ambient"] = value(fast.min_ambient as f64);
    doc["graphics"]["embedded_effects"]["fast_ao"]["luminance_protection"] =
        value(fast.luminance_protection as f64);
    doc["graphics"]["embedded_effects"]["fast_ao"]["stability"] = value(fast.stability as f64);
    doc["graphics"]["embedded_effects"]["fast_ao"]["first_person_mask"] =
        value(fast.first_person_mask as f64);
    doc["graphics"]["embedded_effects"]["fast_ao"]["fog_fade"] = value(fast.fog_fade as f64);

    let contact = &config.contact_ao;
    doc["graphics"]["embedded_effects"]["contact_ao"]["enabled"] = value(contact.enabled);
    doc["graphics"]["embedded_effects"]["contact_ao"]["strength"] = value(contact.strength as f64);
    doc["graphics"]["embedded_effects"]["contact_ao"]["radius_pixels"] =
        value(contact.radius_pixels as f64);
    doc["graphics"]["embedded_effects"]["contact_ao"]["range_scale"] =
        value(contact.range_scale as f64);
    doc["graphics"]["embedded_effects"]["contact_ao"]["bias_scale"] =
        value(contact.bias_scale as f64);
    doc["graphics"]["embedded_effects"]["contact_ao"]["depth_reversed"] =
        value(contact.depth_reversed);
    doc["graphics"]["embedded_effects"]["contact_ao"]["min_ambient"] =
        value(contact.min_ambient as f64);
    doc["graphics"]["embedded_effects"]["contact_ao"]["stability"] =
        value(contact.stability as f64);
    doc["graphics"]["embedded_effects"]["contact_ao"]["first_person_mask"] =
        value(contact.first_person_mask as f64);
    doc["graphics"]["embedded_effects"]["contact_ao"]["fog_fade"] = value(contact.fog_fade as f64);

    let bloom = &config.blooming_hdr;
    doc["graphics"]["embedded_effects"]["blooming_hdr"]["enabled"] = value(bloom.enabled);
    doc["graphics"]["embedded_effects"]["blooming_hdr"]["bloom_intensity"] =
        value(bloom.bloom_intensity as f64);
    doc["graphics"]["embedded_effects"]["blooming_hdr"]["bright_threshold"] =
        value(bloom.bright_threshold as f64);
    doc["graphics"]["embedded_effects"]["blooming_hdr"]["radius_pixels"] =
        value(bloom.radius_pixels as f64);
    doc["graphics"]["embedded_effects"]["blooming_hdr"]["soft_knee"] =
        value(bloom.soft_knee as f64);
    doc["graphics"]["embedded_effects"]["blooming_hdr"]["exposure_bias"] =
        value(bloom.exposure_bias as f64);
    doc["graphics"]["embedded_effects"]["blooming_hdr"]["highlight_shoulder"] =
        value(bloom.highlight_shoulder as f64);
    doc["graphics"]["embedded_effects"]["blooming_hdr"]["saturation"] =
        value(bloom.saturation as f64);
    doc["graphics"]["embedded_effects"]["blooming_hdr"]["warmth"] = value(bloom.warmth as f64);
    doc["graphics"]["embedded_effects"]["blooming_hdr"]["shadow_lift"] =
        value(bloom.shadow_lift as f64);
    doc["graphics"]["embedded_effects"]["blooming_hdr"]["dither"] = value(bloom.dither as f64);
    doc["graphics"]["embedded_effects"]["blooming_hdr"]["debug_bloom"] = value(bloom.debug_bloom);
    doc["graphics"]["embedded_effects"]["blooming_hdr"]["atmosphere"] =
        value(bloom.atmosphere as f64);

    let sun = &config.sunshafts;
    doc["graphics"]["embedded_effects"]["sunshafts"]["enabled"] = value(sun.enabled);
    doc["graphics"]["embedded_effects"]["sunshafts"]["intensity"] = value(sun.intensity as f64);
    doc["graphics"]["embedded_effects"]["sunshafts"]["exposure"] = value(sun.exposure as f64);
    doc["graphics"]["embedded_effects"]["sunshafts"]["decay"] = value(sun.decay as f64);
    doc["graphics"]["embedded_effects"]["sunshafts"]["density"] = value(sun.density as f64);
    doc["graphics"]["embedded_effects"]["sunshafts"]["force"] = value(sun.force as f64);
    doc["graphics"]["embedded_effects"]["sunshafts"]["bright_threshold"] =
        value(sun.bright_threshold as f64);
    doc["graphics"]["embedded_effects"]["sunshafts"]["warmth"] = value(sun.warmth as f64);
    doc["graphics"]["embedded_effects"]["sunshafts"]["first_person_occlusion"] =
        value(sun.first_person_occlusion as f64);
    doc["graphics"]["embedded_effects"]["sunshafts"]["sun_falloff"] = value(sun.sun_falloff as f64);
    doc["graphics"]["embedded_effects"]["sunshafts"]["depth_reversed"] = value(sun.depth_reversed);
    doc["graphics"]["embedded_effects"]["sunshafts"]["debug_mask"] = value(sun.debug_mask);
    doc["graphics"]["embedded_effects"]["sunshafts"]["sun_sample_px"] =
        value(sun.sun_sample_px as i64);
    doc["graphics"]["embedded_effects"]["sunshafts"]["glare_radius"] =
        value(sun.glare_radius as f64);
    doc["graphics"]["embedded_effects"]["sunshafts"]["occlusion_softness"] =
        value(sun.occlusion_softness as f64);
}

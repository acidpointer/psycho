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
    pub(crate) native_sky: NativeSkyConfig,
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
            native_sky: NativeSkyConfig::default(),
            embedded_effects: EmbeddedEffectsConfig::default(),
            depth_provider: DepthProviderConfig::default(),
            menu_toggle_key: 0x2D,
            shader_scan_interval_ms: 200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct NativeSkyConfig {
    pub(crate) enabled: bool,
    pub(crate) atmosphere_thickness: f32,
    pub(crate) sun_influence: f32,
    pub(crate) sun_strength: f32,
    pub(crate) glare_strength: f32,
    pub(crate) star_strength: f32,
    pub(crate) star_twinkle: f32,
    pub(crate) cloud_transparency: f32,
    pub(crate) cloud_brightness: f32,
    pub(crate) cloud_normals: bool,
    pub(crate) use_sun_disk_color: bool,
    pub(crate) sunset_red: f32,
    pub(crate) sunset_green: f32,
    pub(crate) sunset_blue: f32,
    pub(crate) sky_multiplier: f32,
}

impl Default for NativeSkyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            atmosphere_thickness: 0.7068965,
            sun_influence: 1.291271,
            sun_strength: 1.517241,
            glare_strength: 0.8965517,
            star_strength: 1.0,
            star_twinkle: 1.0,
            cloud_transparency: 0.3610992,
            cloud_brightness: 1.305171,
            cloud_normals: false,
            use_sun_disk_color: false,
            sunset_red: 0.5,
            sunset_green: 0.0,
            sunset_blue: 0.03,
            sky_multiplier: 2.043103,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct NativePbrConfig {
    pub(crate) enabled: bool,
    pub(crate) debug_log_draws: bool,
    pub(crate) object_roughness_scale: f32,
    pub(crate) object_light_scale: f32,
    pub(crate) object_ambient_scale: f32,
    pub(crate) object_albedo_saturation: f32,
    #[serde(alias = "metallicness")]
    pub(crate) terrain_metallicness: f32,
    #[serde(alias = "roughness_scale")]
    pub(crate) terrain_roughness_scale: f32,
    #[serde(alias = "light_scale")]
    pub(crate) terrain_light_scale: f32,
    #[serde(alias = "ambient_scale")]
    pub(crate) terrain_ambient_scale: f32,
    #[serde(alias = "albedo_saturation")]
    pub(crate) terrain_albedo_saturation: f32,
    pub(crate) terrain_lod_noise_scale: f32,
    pub(crate) terrain_lod_noise_tile: f32,
}

impl Default for NativePbrConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            debug_log_draws: false,
            object_roughness_scale: 1.0,
            object_light_scale: 1.0,
            object_ambient_scale: 1.0,
            object_albedo_saturation: 1.0,
            terrain_metallicness: 0.0,
            terrain_roughness_scale: 0.82,
            terrain_light_scale: 1.15,
            terrain_ambient_scale: 1.10,
            terrain_albedo_saturation: 1.02,
            terrain_lod_noise_scale: 1.0,
            terrain_lod_noise_tile: 1.75,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct EmbeddedEffectsConfig {
    pub(crate) fast_ao: FastAoConfig,
    pub(crate) contact_ao: ContactAoConfig,
    pub(crate) blooming_hdr: BloomingHdrConfig,
    pub(crate) sunshafts: SunshaftsConfig,
    pub(crate) depth_of_field: DepthOfFieldConfig,
}

impl Default for EmbeddedEffectsConfig {
    fn default() -> Self {
        Self {
            fast_ao: FastAoConfig::default(),
            contact_ao: ContactAoConfig::default(),
            blooming_hdr: BloomingHdrConfig::default(),
            sunshafts: SunshaftsConfig::default(),
            depth_of_field: DepthOfFieldConfig::default(),
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
            strength: 1.36793,
            radius_scale: 71.698_27,
            max_radius_pixels: 7.6,
            range_scale: 0.07976293,
            debug_depth: false,
            depth_reversed: true,
            min_ambient: 0.1543535,
            luminance_protection: 0.45,
            stability: 0.5875,
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
            strength: 0.4291376,
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
            intensity: 0.3076724,
            exposure: 0.2062068,
            decay: 1.017446,
            density: 0.9709481,
            force: 1.015518,
            bright_threshold: 0.7188362,
            warmth: 0.9675861,
            first_person_occlusion: 1.0,
            sun_falloff: 1.088103,
            depth_reversed: true,
            debug_mask: false,
            sun_sample_px: 32,
            glare_radius: 0.07175863,
            occlusion_softness: 0.42,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DofFocusMode {
    #[default]
    Auto,
    Manual,
}

impl DofFocusMode {
    pub(crate) fn index(self) -> i32 {
        match self {
            Self::Auto => 0,
            Self::Manual => 1,
        }
    }

    pub(crate) fn from_index(value: i32) -> Self {
        if value == 1 { Self::Manual } else { Self::Auto }
    }

    fn config_value(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Manual => "manual",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DofQuality {
    Balanced,
    #[default]
    High,
    Ultra,
}

impl DofQuality {
    pub(crate) fn index(self) -> i32 {
        match self {
            Self::Balanced => 0,
            Self::High => 1,
            Self::Ultra => 2,
        }
    }

    pub(crate) fn from_index(value: i32) -> Self {
        match value {
            0 => Self::Balanced,
            2 => Self::Ultra,
            _ => Self::High,
        }
    }

    fn config_value(self) -> &'static str {
        match self {
            Self::Balanced => "balanced",
            Self::High => "high",
            Self::Ultra => "ultra",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DofBlurStyle {
    Round,
    #[default]
    Soft,
}

impl DofBlurStyle {
    pub(crate) fn index(self) -> i32 {
        match self {
            Self::Round => 0,
            Self::Soft => 1,
        }
    }

    pub(crate) fn from_index(value: i32) -> Self {
        if value == 0 { Self::Round } else { Self::Soft }
    }

    fn config_value(self) -> &'static str {
        match self {
            Self::Round => "round",
            Self::Soft => "soft",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct DepthOfFieldConfig {
    pub(crate) enabled: bool,
    pub(crate) respect_vanilla_dof: bool,
    pub(crate) focus_mode: DofFocusMode,
    pub(crate) quality: DofQuality,
    pub(crate) blur_style: DofBlurStyle,
    pub(crate) manual_focus_distance: f32,
    pub(crate) focus_sample_radius: f32,
    pub(crate) focus_cluster_tolerance: f32,
    pub(crate) focus_deadband: f32,
    pub(crate) focus_near_seconds: f32,
    pub(crate) focus_far_seconds: f32,
    pub(crate) focus_range: f32,
    pub(crate) far_focus_range: f32,
    pub(crate) near_strength: f32,
    pub(crate) far_strength: f32,
    pub(crate) near_radius_pixels: f32,
    pub(crate) far_radius_pixels: f32,
    pub(crate) first_person_strength: f32,
    pub(crate) distant_blur_strength: f32,
    pub(crate) distant_blur_start: f32,
    pub(crate) distant_blur_end: f32,
    pub(crate) sky_blur_strength: f32,
    pub(crate) softness: f32,
}

impl Default for DepthOfFieldConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            respect_vanilla_dof: true,
            focus_mode: DofFocusMode::Auto,
            quality: DofQuality::High,
            blur_style: DofBlurStyle::Soft,
            manual_focus_distance: 2_000.0,
            focus_sample_radius: 0.055,
            focus_cluster_tolerance: 0.18,
            focus_deadband: 0.025,
            focus_near_seconds: 0.12,
            focus_far_seconds: 0.28,
            focus_range: 0.55,
            far_focus_range: 0.70,
            near_strength: 0.35,
            far_strength: 0.35,
            near_radius_pixels: 10.0,
            far_radius_pixels: 48.0,
            first_person_strength: 0.2,
            distant_blur_strength: 0.6413795,
            distant_blur_start: 21_551.82,
            distant_blur_end: 55_172.29,
            sky_blur_strength: 0.125,
            softness: 0.9517241,
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

pub(crate) fn load_menu_config_from_disk() -> Result<GraphicsMenuConfig> {
    let config = Config::load::<PsychoGraphicsConfig>(CONFIG_PATH)
        .with_context(|| format!("failed to reload {CONFIG_PATH}"))?;
    Ok(GraphicsMenuConfig::from(&config))
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct GraphicsMenuConfig {
    pub(crate) screen_space_shaders: bool,
    pub(crate) native_pbr: NativePbrConfig,
    pub(crate) native_sky: NativeSkyConfig,
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
            native_sky: graphics.native_sky,
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
            native_sky: value.graphics.native_sky,
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
            crate::shaders::EmbeddedEffectKind::Sunshafts
            | crate::shaders::EmbeddedEffectKind::DepthOfField => ShaderPhase::ScenePostImageSpace,
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
    save_native_sky_config(&mut doc, &config.native_sky);
    doc["graphics"]["native_pbr"]["enabled"] = value(config.native_pbr.enabled);
    if let Some(native_pbr) = doc["graphics"]["native_pbr"].as_table_mut() {
        native_pbr.remove("terrain_enabled");
        native_pbr.remove("close_terrain_enabled");
        native_pbr.remove("terrain_fade_enabled");
        native_pbr.remove("terrain_lod_enabled");
        native_pbr.remove("object_default");
        native_pbr.remove("object_rain");
        native_pbr.remove("object_night");
        native_pbr.remove("object_night_rain");
        native_pbr.remove("object_interior");
        native_pbr.remove("terrain_default");
        native_pbr.remove("terrain_rain");
        native_pbr.remove("terrain_night");
        native_pbr.remove("terrain_night_rain");
    }
    doc["graphics"]["native_pbr"]["debug_log_draws"] = value(config.native_pbr.debug_log_draws);
    doc["graphics"]["native_pbr"]["object_roughness_scale"] =
        value(config.native_pbr.object_roughness_scale as f64);
    doc["graphics"]["native_pbr"]["object_light_scale"] =
        value(config.native_pbr.object_light_scale as f64);
    doc["graphics"]["native_pbr"]["object_ambient_scale"] =
        value(config.native_pbr.object_ambient_scale as f64);
    doc["graphics"]["native_pbr"]["object_albedo_saturation"] =
        value(config.native_pbr.object_albedo_saturation as f64);
    doc["graphics"]["native_pbr"]["terrain_metallicness"] =
        value(config.native_pbr.terrain_metallicness as f64);
    doc["graphics"]["native_pbr"]["terrain_roughness_scale"] =
        value(config.native_pbr.terrain_roughness_scale as f64);
    doc["graphics"]["native_pbr"]["terrain_light_scale"] =
        value(config.native_pbr.terrain_light_scale as f64);
    doc["graphics"]["native_pbr"]["terrain_ambient_scale"] =
        value(config.native_pbr.terrain_ambient_scale as f64);
    doc["graphics"]["native_pbr"]["terrain_albedo_saturation"] =
        value(config.native_pbr.terrain_albedo_saturation as f64);
    doc["graphics"]["native_pbr"]["terrain_lod_noise_scale"] =
        value(config.native_pbr.terrain_lod_noise_scale as f64);
    doc["graphics"]["native_pbr"]["terrain_lod_noise_tile"] =
        value(config.native_pbr.terrain_lod_noise_tile as f64);
    if let Some(native_pbr) = doc["graphics"]["native_pbr"].as_table_mut() {
        native_pbr.remove("experimental_shader_replacement");
        native_pbr.remove("require_vanilla_prologues");
        native_pbr.remove("metallicness");
        native_pbr.remove("roughness_scale");
        native_pbr.remove("light_scale");
        native_pbr.remove("ambient_scale");
        native_pbr.remove("albedo_saturation");
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

fn save_native_sky_config(doc: &mut DocumentMut, config: &NativeSkyConfig) {
    doc["graphics"]["native_sky"]["enabled"] = value(config.enabled);
    doc["graphics"]["native_sky"]["atmosphere_thickness"] =
        value(config.atmosphere_thickness as f64);
    doc["graphics"]["native_sky"]["sun_influence"] = value(config.sun_influence as f64);
    doc["graphics"]["native_sky"]["sun_strength"] = value(config.sun_strength as f64);
    doc["graphics"]["native_sky"]["glare_strength"] = value(config.glare_strength as f64);
    doc["graphics"]["native_sky"]["star_strength"] = value(config.star_strength as f64);
    doc["graphics"]["native_sky"]["star_twinkle"] = value(config.star_twinkle as f64);
    doc["graphics"]["native_sky"]["cloud_transparency"] = value(config.cloud_transparency as f64);
    doc["graphics"]["native_sky"]["cloud_brightness"] = value(config.cloud_brightness as f64);
    doc["graphics"]["native_sky"]["cloud_normals"] = value(config.cloud_normals);
    doc["graphics"]["native_sky"]["use_sun_disk_color"] = value(config.use_sun_disk_color);
    doc["graphics"]["native_sky"]["sunset_red"] = value(config.sunset_red as f64);
    doc["graphics"]["native_sky"]["sunset_green"] = value(config.sunset_green as f64);
    doc["graphics"]["native_sky"]["sunset_blue"] = value(config.sunset_blue as f64);
    doc["graphics"]["native_sky"]["sky_multiplier"] = value(config.sky_multiplier as f64);
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

    let dof = &config.depth_of_field;
    doc["graphics"]["embedded_effects"]["depth_of_field"]["enabled"] = value(dof.enabled);
    doc["graphics"]["embedded_effects"]["depth_of_field"]["respect_vanilla_dof"] =
        value(dof.respect_vanilla_dof);
    doc["graphics"]["embedded_effects"]["depth_of_field"]["focus_mode"] =
        value(dof.focus_mode.config_value());
    doc["graphics"]["embedded_effects"]["depth_of_field"]["quality"] =
        value(dof.quality.config_value());
    doc["graphics"]["embedded_effects"]["depth_of_field"]["blur_style"] =
        value(dof.blur_style.config_value());
    doc["graphics"]["embedded_effects"]["depth_of_field"]["manual_focus_distance"] =
        value(dof.manual_focus_distance as f64);
    doc["graphics"]["embedded_effects"]["depth_of_field"]["focus_sample_radius"] =
        value(dof.focus_sample_radius as f64);
    doc["graphics"]["embedded_effects"]["depth_of_field"]["focus_cluster_tolerance"] =
        value(dof.focus_cluster_tolerance as f64);
    doc["graphics"]["embedded_effects"]["depth_of_field"]["focus_deadband"] =
        value(dof.focus_deadband as f64);
    doc["graphics"]["embedded_effects"]["depth_of_field"]["focus_near_seconds"] =
        value(dof.focus_near_seconds as f64);
    doc["graphics"]["embedded_effects"]["depth_of_field"]["focus_far_seconds"] =
        value(dof.focus_far_seconds as f64);
    doc["graphics"]["embedded_effects"]["depth_of_field"]["focus_range"] =
        value(dof.focus_range as f64);
    doc["graphics"]["embedded_effects"]["depth_of_field"]["far_focus_range"] =
        value(dof.far_focus_range as f64);
    doc["graphics"]["embedded_effects"]["depth_of_field"]["near_strength"] =
        value(dof.near_strength as f64);
    doc["graphics"]["embedded_effects"]["depth_of_field"]["far_strength"] =
        value(dof.far_strength as f64);
    doc["graphics"]["embedded_effects"]["depth_of_field"]["near_radius_pixels"] =
        value(dof.near_radius_pixels as f64);
    doc["graphics"]["embedded_effects"]["depth_of_field"]["far_radius_pixels"] =
        value(dof.far_radius_pixels as f64);
    doc["graphics"]["embedded_effects"]["depth_of_field"]["first_person_strength"] =
        value(dof.first_person_strength as f64);
    doc["graphics"]["embedded_effects"]["depth_of_field"]["distant_blur_strength"] =
        value(dof.distant_blur_strength as f64);
    doc["graphics"]["embedded_effects"]["depth_of_field"]["distant_blur_start"] =
        value(dof.distant_blur_start as f64);
    doc["graphics"]["embedded_effects"]["depth_of_field"]["distant_blur_end"] =
        value(dof.distant_blur_end as f64);
    doc["graphics"]["embedded_effects"]["depth_of_field"]["sky_blur_strength"] =
        value(dof.sky_blur_strength as f64);
    doc["graphics"]["embedded_effects"]["depth_of_field"]["softness"] = value(dof.softness as f64);
}

#[cfg(test)]
mod tests {
    use super::NativePbrConfig;

    #[test]
    fn legacy_pbr_profile_migrates_to_terrain_only() {
        let config: NativePbrConfig = toml::from_str(
            r#"
metallicness = 0.2
roughness_scale = 0.82
light_scale = 1.15
ambient_scale = 1.1
albedo_saturation = 1.02
"#,
        )
        .expect("legacy native PBR config must remain readable");

        assert_eq!(config.object_roughness_scale, 1.0);
        assert_eq!(config.object_light_scale, 1.0);
        assert_eq!(config.object_ambient_scale, 1.0);
        assert_eq!(config.object_albedo_saturation, 1.0);
        assert_eq!(config.terrain_metallicness, 0.2);
        assert_eq!(config.terrain_roughness_scale, 0.82);
        assert_eq!(config.terrain_light_scale, 1.15);
        assert_eq!(config.terrain_ambient_scale, 1.1);
        assert_eq!(config.terrain_albedo_saturation, 1.02);
    }
}

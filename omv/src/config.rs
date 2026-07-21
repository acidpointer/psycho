//! Graphics module configuration.

use std::sync::OnceLock;
use std::{fs, path::Path};

use anyhow::{Context, Result};
use libpsycho::config::Config;
use serde::{Deserialize, Serialize};
use toml_edit::{DocumentMut, value};

use crate::shaders::ShaderPhase;

fn finite_clamp(value: f32, fallback: f32, min: f32, max: f32) -> f32 {
    if value.is_finite() {
        value.clamp(min, max)
    } else {
        fallback
    }
}

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

impl NativePbrConfig {
    fn sanitized(mut self) -> Self {
        self.terrain_lod_noise_scale = finite_clamp(self.terrain_lod_noise_scale, 1.0, 0.0, 1.0);
        self
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct EmbeddedEffectsConfig {
    pub(crate) fast_ao: FastAoConfig,
    pub(crate) contact_ao: ContactAoConfig,
    pub(crate) volumetric_fog: VolumetricFogConfig,
    pub(crate) volumetric_lighting: VolumetricLightingConfig,
    pub(crate) blooming_hdr: BloomingHdrConfig,
    pub(crate) color_grade: ColorGradeConfig,
    pub(crate) sunshafts: SunshaftsConfig,
    pub(crate) depth_of_field: DepthOfFieldConfig,
    pub(crate) temporal_aa: TemporalAaConfig,
    pub(crate) fast_fxaa: FastFxaaConfig,
    pub(crate) nfaa: NfaaConfig,
    pub(crate) axaa: AxaaConfig,
    pub(crate) dlaa: DlaaConfig,
    pub(crate) smaa: SmaaConfig,
}

impl Default for EmbeddedEffectsConfig {
    fn default() -> Self {
        Self {
            fast_ao: FastAoConfig::default(),
            contact_ao: ContactAoConfig::default(),
            volumetric_fog: VolumetricFogConfig::default(),
            volumetric_lighting: VolumetricLightingConfig::default(),
            blooming_hdr: BloomingHdrConfig::default(),
            color_grade: ColorGradeConfig::default(),
            sunshafts: SunshaftsConfig::default(),
            depth_of_field: DepthOfFieldConfig::default(),
            temporal_aa: TemporalAaConfig::default(),
            fast_fxaa: FastFxaaConfig::default(),
            nfaa: NfaaConfig::default(),
            axaa: AxaaConfig::default(),
            dlaa: DlaaConfig::default(),
            smaa: SmaaConfig::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AtmosphereQuality {
    Performance,
    #[default]
    High,
    Ultra,
}

impl AtmosphereQuality {
    pub(crate) fn index(self) -> i32 {
        match self {
            Self::Performance => 0,
            Self::High => 1,
            Self::Ultra => 2,
        }
    }

    pub(crate) fn from_index(value: i32) -> Self {
        match value {
            0 => Self::Performance,
            2 => Self::Ultra,
            _ => Self::High,
        }
    }

    fn config_value(self) -> &'static str {
        match self {
            Self::Performance => "performance",
            Self::High => "high",
            Self::Ultra => "ultra",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct VolumetricFogConfig {
    pub(crate) enabled: bool,
    pub(crate) quality: AtmosphereQuality,
    pub(crate) density: f32,
    pub(crate) height_density: f32,
    pub(crate) height_falloff: f32,
    pub(crate) base_height: f32,
    pub(crate) max_distance: f32,
    pub(crate) scattering_albedo: f32,
    pub(crate) noise_amount: f32,
    pub(crate) noise_scale: f32,
    pub(crate) noise_speed: f32,
    pub(crate) temporal_stability: f32,
    pub(crate) debug_view: i32,
}

impl Default for VolumetricFogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            quality: AtmosphereQuality::High,
            density: 0.0,
            height_density: 0.0000025,
            height_falloff: 0.00008,
            base_height: 0.0,
            max_distance: 120_000.0,
            scattering_albedo: 0.88,
            noise_amount: 0.18,
            noise_scale: 0.00035,
            noise_speed: 0.02,
            temporal_stability: 0.9,
            debug_view: 0,
        }
    }
}

impl VolumetricFogConfig {
    fn sanitized(mut self) -> Self {
        self.density = finite_clamp(self.density, 0.0, 0.0, 0.001);
        self.height_density = finite_clamp(self.height_density, 0.0000025, 0.0, 0.001);
        self.height_falloff = finite_clamp(self.height_falloff, 0.00008, 0.000001, 0.01);
        self.base_height = finite_clamp(self.base_height, 0.0, -100_000.0, 100_000.0);
        self.max_distance = finite_clamp(self.max_distance, 120_000.0, 1_000.0, 250_000.0);
        self.scattering_albedo = finite_clamp(self.scattering_albedo, 0.88, 0.0, 1.0);
        self.noise_amount = finite_clamp(self.noise_amount, 0.18, 0.0, 1.0);
        self.noise_scale = finite_clamp(self.noise_scale, 0.00035, 0.000001, 0.05);
        self.noise_speed = finite_clamp(self.noise_speed, 0.02, 0.0, 1.0);
        self.temporal_stability = finite_clamp(self.temporal_stability, 0.9, 0.0, 0.98);
        self.debug_view = self.debug_view.clamp(0, 8);
        self
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct VolumetricLightingConfig {
    pub(crate) enabled: bool,
    pub(crate) intensity: f32,
    pub(crate) medium_density: f32,
    pub(crate) max_distance: f32,
    pub(crate) anisotropy: f32,
    pub(crate) shaft_strength: f32,
    pub(crate) sun_disk_boost: f32,
    pub(crate) shaft_quality: AtmosphereQuality,
    pub(crate) local_lights_enabled: bool,
    pub(crate) local_lights_intensity: f32,
    pub(crate) local_lights_quality: AtmosphereQuality,
    pub(crate) temporal_stability: f32,
    pub(crate) debug_view: i32,
}

impl Default for VolumetricLightingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            intensity: 0.95,
            medium_density: 0.0000025,
            max_distance: 120_000.0,
            anisotropy: 0.58,
            shaft_strength: 0.72,
            sun_disk_boost: 1.0,
            shaft_quality: AtmosphereQuality::High,
            local_lights_enabled: true,
            local_lights_intensity: 1.5,
            local_lights_quality: AtmosphereQuality::High,
            temporal_stability: 0.9,
            debug_view: 0,
        }
    }
}

impl VolumetricLightingConfig {
    fn sanitized(mut self) -> Self {
        self.intensity = finite_clamp(self.intensity, 0.95, 0.0, 8.0);
        self.medium_density = finite_clamp(self.medium_density, 0.0000025, 0.0, 0.001);
        self.max_distance = finite_clamp(self.max_distance, 120_000.0, 1_000.0, 250_000.0);
        self.anisotropy = finite_clamp(self.anisotropy, 0.58, -0.8, 0.9);
        self.shaft_strength = finite_clamp(self.shaft_strength, 0.72, 0.0, 1.0);
        self.sun_disk_boost = finite_clamp(self.sun_disk_boost, 1.0, 0.0, 8.0);
        self.local_lights_intensity = finite_clamp(self.local_lights_intensity, 1.5, 0.0, 4.0);
        self.temporal_stability = finite_clamp(self.temporal_stability, 0.9, 0.0, 0.98);
        self.debug_view = self.debug_view.clamp(0, 8);
        self
    }
}

impl EmbeddedEffectsConfig {
    fn sanitized(mut self) -> Self {
        self.volumetric_fog = self.volumetric_fog.sanitized();
        self.volumetric_lighting = self.volumetric_lighting.sanitized();
        self.blooming_hdr = self.blooming_hdr.sanitized();
        self.color_grade = self.color_grade.sanitized();
        self.sunshafts = self.sunshafts.sanitized();
        self
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct TemporalAaConfig {
    pub(crate) enabled: bool,
    pub(crate) history_weight: f32,
    pub(crate) clamp_strength: f32,
    pub(crate) sharpness: f32,
    pub(crate) jitter_scale: f32,
}

impl Default for TemporalAaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            history_weight: 0.90,
            clamp_strength: 1.0,
            sharpness: 0.10,
            jitter_scale: 1.0,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct FastFxaaConfig {
    pub(crate) enabled: bool,
    pub(crate) edge_threshold: f32,
    pub(crate) reduce: f32,
    pub(crate) span: f32,
    pub(crate) blend: f32,
}

impl Default for FastFxaaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            edge_threshold: 0.08,
            reduce: 0.25,
            span: 3.0,
            blend: 0.75,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct NfaaConfig {
    pub(crate) enabled: bool,
    pub(crate) aa_power: f32,
    pub(crate) mask_adjust: f32,
    pub(crate) debug_view: i32,
}

impl Default for NfaaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            aa_power: 16.0,
            mask_adjust: 1.0,
            debug_view: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct AxaaConfig {
    pub(crate) enabled: bool,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct DlaaConfig {
    pub(crate) enabled: bool,
    pub(crate) debug_view: i32,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct SmaaConfig {
    pub(crate) enabled: bool,
    pub(crate) edge_detection: i32,
    pub(crate) threshold: f32,
    pub(crate) corner_rounding: f32,
    pub(crate) debug_view: i32,
}

impl Default for SmaaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            edge_detection: 1,
            threshold: 0.10,
            corner_rounding: 25.0,
            debug_view: 0,
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
            bloom_intensity: 0.34,
            bright_threshold: 0.62,
            radius_pixels: 2.8,
            soft_knee: 0.28,
            exposure_bias: 0.02,
            highlight_shoulder: 0.58,
            saturation: 0.92,
            warmth: 0.18,
            shadow_lift: 0.10,
            dither: 0.32,
            debug_bloom: false,
            atmosphere: 0.24,
        }
    }
}

impl BloomingHdrConfig {
    fn sanitized(mut self) -> Self {
        self.bloom_intensity = finite_clamp(self.bloom_intensity, 0.34, 0.0, 1.5);
        self.bright_threshold = finite_clamp(self.bright_threshold, 0.62, 0.25, 0.95);
        self.radius_pixels = finite_clamp(self.radius_pixels, 2.8, 0.5, 7.0);
        self.soft_knee = finite_clamp(self.soft_knee, 0.28, 0.02, 0.65);
        self.exposure_bias = finite_clamp(self.exposure_bias, 0.02, -0.5, 0.5);
        self.highlight_shoulder = finite_clamp(self.highlight_shoulder, 0.58, 0.0, 1.0);
        self.saturation = finite_clamp(self.saturation, 0.92, 0.0, 1.5);
        self.warmth = finite_clamp(self.warmth, 0.18, -1.0, 1.0);
        self.shadow_lift = finite_clamp(self.shadow_lift, 0.10, 0.0, 1.0);
        self.dither = finite_clamp(self.dither, 0.32, 0.0, 1.0);
        self.atmosphere = finite_clamp(self.atmosphere, 0.24, 0.0, 1.0);
        self
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct ColorGradeConfig {
    pub(crate) enabled: bool,
    pub(crate) strength: f32,
    pub(crate) color_grading_enabled: bool,
    pub(crate) exposure: f32,
    pub(crate) contrast: f32,
    pub(crate) saturation: f32,
    pub(crate) vibrance: f32,
    pub(crate) temperature: f32,
    pub(crate) tint: f32,
    pub(crate) black_fade: f32,
    pub(crate) highlight_rolloff: f32,
    pub(crate) lut_enabled: bool,
    pub(crate) lut_file_id: u32,
    pub(crate) lut_strength: f32,
    pub(crate) environment_response: f32,
    pub(crate) deband_enabled: bool,
    pub(crate) deband: f32,
    pub(crate) film_grain_enabled: bool,
    pub(crate) film_grain: f32,
    pub(crate) vignette_enabled: bool,
    pub(crate) vignette: f32,
    pub(crate) halation_enabled: bool,
    pub(crate) halation: f32,
    pub(crate) chromatic_aberration_enabled: bool,
    pub(crate) chromatic_aberration: f32,
    pub(crate) debug_split: bool,
}

impl Default for ColorGradeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            strength: 0.68,
            color_grading_enabled: true,
            exposure: 0.0,
            contrast: 0.045,
            saturation: 0.98,
            vibrance: 0.075,
            temperature: 0.015,
            tint: 0.006,
            black_fade: 0.012,
            highlight_rolloff: 0.16,
            lut_enabled: true,
            lut_file_id: 97_154_384,
            lut_strength: 0.42,
            environment_response: 0.45,
            deband_enabled: true,
            deband: 0.55,
            film_grain_enabled: true,
            film_grain: 0.16,
            vignette_enabled: true,
            vignette: 0.035,
            halation_enabled: true,
            halation: 0.12,
            chromatic_aberration_enabled: false,
            chromatic_aberration: 0.85,
            debug_split: false,
        }
    }
}

impl ColorGradeConfig {
    fn sanitized(mut self) -> Self {
        self.strength = finite_clamp(self.strength, 0.68, 0.0, 1.0);
        self.exposure = finite_clamp(self.exposure, 0.0, -1.5, 1.5);
        self.contrast = finite_clamp(self.contrast, 0.045, -0.5, 0.5);
        self.saturation = finite_clamp(self.saturation, 0.98, 0.0, 2.0);
        self.vibrance = finite_clamp(self.vibrance, 0.075, -1.0, 1.0);
        self.temperature = finite_clamp(self.temperature, 0.015, -1.0, 1.0);
        self.tint = finite_clamp(self.tint, 0.006, -1.0, 1.0);
        self.black_fade = finite_clamp(self.black_fade, 0.012, 0.0, 1.0);
        self.highlight_rolloff = finite_clamp(self.highlight_rolloff, 0.16, 0.0, 1.0);
        self.lut_strength = finite_clamp(self.lut_strength, 0.42, 0.0, 1.0);
        self.environment_response = finite_clamp(self.environment_response, 0.45, 0.0, 1.0);
        self.deband = finite_clamp(self.deband, 0.55, 0.0, 1.0);
        self.film_grain = finite_clamp(self.film_grain, 0.16, 0.0, 1.0);
        self.vignette = finite_clamp(self.vignette, 0.035, 0.0, 1.0);
        self.halation = finite_clamp(self.halation, 0.12, 0.0, 1.0);
        self.chromatic_aberration = finite_clamp(self.chromatic_aberration, 0.85, 0.0, 4.0);
        self
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
    pub(crate) medium_response: f32,
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
            medium_response: 1.0,
            occlusion_softness: 0.42,
        }
    }
}

impl SunshaftsConfig {
    fn sanitized(mut self) -> Self {
        let defaults = Self::default();
        self.intensity = finite_clamp(self.intensity, defaults.intensity, 0.0, 2.5);
        self.exposure = finite_clamp(self.exposure, defaults.exposure, 0.0, 2.8);
        self.decay = finite_clamp(self.decay, defaults.decay, 0.65, 1.035);
        self.density = finite_clamp(self.density, defaults.density, 0.2, 1.35);
        self.force = finite_clamp(self.force, defaults.force, 0.0, 4.0);
        self.bright_threshold =
            finite_clamp(self.bright_threshold, defaults.bright_threshold, 0.0, 1.0);
        self.warmth = finite_clamp(self.warmth, defaults.warmth, 0.0, 1.0);
        self.first_person_occlusion = finite_clamp(
            self.first_person_occlusion,
            defaults.first_person_occlusion,
            0.0,
            1.0,
        );
        self.sun_falloff = finite_clamp(self.sun_falloff, defaults.sun_falloff, 0.16, 1.2);
        self.sun_sample_px = self.sun_sample_px.clamp(2, 48);
        self.glare_radius = finite_clamp(self.glare_radius, defaults.glare_radius, 0.01, 0.08);
        self.medium_response =
            finite_clamp(self.medium_response, defaults.medium_response, 0.0, 2.0);
        self.occlusion_softness = finite_clamp(
            self.occlusion_softness,
            defaults.occlusion_softness,
            0.0,
            0.75,
        );
        self
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
            native_pbr: value.graphics.native_pbr.sanitized(),
            native_sky: value.graphics.native_sky,
            embedded_effects: value.graphics.embedded_effects.sanitized(),
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
            crate::shaders::EmbeddedEffectKind::VolumetricFog
            | crate::shaders::EmbeddedEffectKind::VolumetricLighting => {
                ShaderPhase::ScenePostImageSpace
            }
            crate::shaders::EmbeddedEffectKind::BloomingHdr
            | crate::shaders::EmbeddedEffectKind::ColorGrade => ShaderPhase::FinalImageSpace,
            crate::shaders::EmbeddedEffectKind::FastFxaa
            | crate::shaders::EmbeddedEffectKind::Nfaa
            | crate::shaders::EmbeddedEffectKind::Axaa
            | crate::shaders::EmbeddedEffectKind::Dlaa
            | crate::shaders::EmbeddedEffectKind::Smaa => ShaderPhase::FinalImageSpace,
            crate::shaders::EmbeddedEffectKind::Sunshafts
            | crate::shaders::EmbeddedEffectKind::DepthOfField
            | crate::shaders::EmbeddedEffectKind::TemporalAa => ShaderPhase::ScenePostImageSpace,
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
        value(finite_clamp(config.native_pbr.terrain_lod_noise_scale, 1.0, 0.0, 1.0) as f64);
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
    let fog = &config.volumetric_fog;
    doc["graphics"]["embedded_effects"]["volumetric_fog"]["enabled"] = value(fog.enabled);
    doc["graphics"]["embedded_effects"]["volumetric_fog"]["quality"] =
        value(fog.quality.config_value());
    doc["graphics"]["embedded_effects"]["volumetric_fog"]["density"] = value(fog.density as f64);
    doc["graphics"]["embedded_effects"]["volumetric_fog"]["height_density"] =
        value(fog.height_density as f64);
    doc["graphics"]["embedded_effects"]["volumetric_fog"]["height_falloff"] =
        value(fog.height_falloff as f64);
    doc["graphics"]["embedded_effects"]["volumetric_fog"]["base_height"] =
        value(fog.base_height as f64);
    doc["graphics"]["embedded_effects"]["volumetric_fog"]["max_distance"] =
        value(fog.max_distance as f64);
    doc["graphics"]["embedded_effects"]["volumetric_fog"]["scattering_albedo"] =
        value(fog.scattering_albedo as f64);
    doc["graphics"]["embedded_effects"]["volumetric_fog"]["noise_amount"] =
        value(fog.noise_amount as f64);
    doc["graphics"]["embedded_effects"]["volumetric_fog"]["noise_scale"] =
        value(fog.noise_scale as f64);
    doc["graphics"]["embedded_effects"]["volumetric_fog"]["noise_speed"] =
        value(fog.noise_speed as f64);
    doc["graphics"]["embedded_effects"]["volumetric_fog"]["temporal_stability"] =
        value(fog.temporal_stability as f64);
    doc["graphics"]["embedded_effects"]["volumetric_fog"]["debug_view"] =
        value(fog.debug_view as i64);

    let lighting = &config.volumetric_lighting;
    doc["graphics"]["embedded_effects"]["volumetric_lighting"]["enabled"] = value(lighting.enabled);
    doc["graphics"]["embedded_effects"]["volumetric_lighting"]["intensity"] =
        value(lighting.intensity as f64);
    doc["graphics"]["embedded_effects"]["volumetric_lighting"]["medium_density"] =
        value(lighting.medium_density as f64);
    doc["graphics"]["embedded_effects"]["volumetric_lighting"]["max_distance"] =
        value(lighting.max_distance as f64);
    doc["graphics"]["embedded_effects"]["volumetric_lighting"]["anisotropy"] =
        value(lighting.anisotropy as f64);
    doc["graphics"]["embedded_effects"]["volumetric_lighting"]["shaft_strength"] =
        value(lighting.shaft_strength as f64);
    doc["graphics"]["embedded_effects"]["volumetric_lighting"]["sun_disk_boost"] =
        value(lighting.sun_disk_boost as f64);
    doc["graphics"]["embedded_effects"]["volumetric_lighting"]["shaft_quality"] =
        value(lighting.shaft_quality.config_value());
    doc["graphics"]["embedded_effects"]["volumetric_lighting"]["local_lights_enabled"] =
        value(lighting.local_lights_enabled);
    doc["graphics"]["embedded_effects"]["volumetric_lighting"]["local_lights_intensity"] =
        value(lighting.local_lights_intensity as f64);
    doc["graphics"]["embedded_effects"]["volumetric_lighting"]["local_lights_quality"] =
        value(lighting.local_lights_quality.config_value());
    doc["graphics"]["embedded_effects"]["volumetric_lighting"]["temporal_stability"] =
        value(lighting.temporal_stability as f64);
    doc["graphics"]["embedded_effects"]["volumetric_lighting"]["debug_view"] =
        value(lighting.debug_view as i64);

    let fast_fxaa = &config.fast_fxaa;
    doc["graphics"]["embedded_effects"]["fast_fxaa"]["enabled"] = value(fast_fxaa.enabled);
    doc["graphics"]["embedded_effects"]["fast_fxaa"]["edge_threshold"] =
        value(fast_fxaa.edge_threshold as f64);
    doc["graphics"]["embedded_effects"]["fast_fxaa"]["reduce"] = value(fast_fxaa.reduce as f64);
    doc["graphics"]["embedded_effects"]["fast_fxaa"]["span"] = value(fast_fxaa.span as f64);
    doc["graphics"]["embedded_effects"]["fast_fxaa"]["blend"] = value(fast_fxaa.blend as f64);

    let nfaa = &config.nfaa;
    doc["graphics"]["embedded_effects"]["nfaa"]["enabled"] = value(nfaa.enabled);
    doc["graphics"]["embedded_effects"]["nfaa"]["aa_power"] = value(nfaa.aa_power as f64);
    doc["graphics"]["embedded_effects"]["nfaa"]["mask_adjust"] = value(nfaa.mask_adjust as f64);
    doc["graphics"]["embedded_effects"]["nfaa"]["debug_view"] = value(nfaa.debug_view as i64);

    doc["graphics"]["embedded_effects"]["axaa"]["enabled"] = value(config.axaa.enabled);
    doc["graphics"]["embedded_effects"]["dlaa"]["enabled"] = value(config.dlaa.enabled);
    doc["graphics"]["embedded_effects"]["dlaa"]["debug_view"] =
        value(config.dlaa.debug_view as i64);

    let smaa = &config.smaa;
    doc["graphics"]["embedded_effects"]["smaa"]["enabled"] = value(smaa.enabled);
    if let Some(smaa_table) = doc["graphics"]["embedded_effects"]["smaa"].as_table_mut() {
        smaa_table.remove("max_search_steps");
    }
    doc["graphics"]["embedded_effects"]["smaa"]["edge_detection"] =
        value(smaa.edge_detection as i64);
    doc["graphics"]["embedded_effects"]["smaa"]["threshold"] = value(smaa.threshold as f64);
    doc["graphics"]["embedded_effects"]["smaa"]["corner_rounding"] =
        value(smaa.corner_rounding as f64);
    doc["graphics"]["embedded_effects"]["smaa"]["debug_view"] = value(smaa.debug_view as i64);

    let taa = &config.temporal_aa;
    doc["graphics"]["embedded_effects"]["temporal_aa"]["enabled"] = value(taa.enabled);
    doc["graphics"]["embedded_effects"]["temporal_aa"]["history_weight"] =
        value(taa.history_weight as f64);
    doc["graphics"]["embedded_effects"]["temporal_aa"]["clamp_strength"] =
        value(taa.clamp_strength as f64);
    doc["graphics"]["embedded_effects"]["temporal_aa"]["sharpness"] = value(taa.sharpness as f64);
    doc["graphics"]["embedded_effects"]["temporal_aa"]["jitter_scale"] =
        value(taa.jitter_scale as f64);
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

    save_color_grade_config(doc, &config.color_grade);

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
    doc["graphics"]["embedded_effects"]["sunshafts"]["medium_response"] =
        value(sun.medium_response as f64);
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

fn save_color_grade_config(doc: &mut DocumentMut, grade: &ColorGradeConfig) {
    if let Some(table) = doc["graphics"]["embedded_effects"]["color_grade"].as_table_mut() {
        table.remove("lut_preset");
    }
    doc["graphics"]["embedded_effects"]["color_grade"]["enabled"] = value(grade.enabled);
    doc["graphics"]["embedded_effects"]["color_grade"]["strength"] = value(grade.strength as f64);
    doc["graphics"]["embedded_effects"]["color_grade"]["color_grading_enabled"] =
        value(grade.color_grading_enabled);
    doc["graphics"]["embedded_effects"]["color_grade"]["exposure"] = value(grade.exposure as f64);
    doc["graphics"]["embedded_effects"]["color_grade"]["contrast"] = value(grade.contrast as f64);
    doc["graphics"]["embedded_effects"]["color_grade"]["saturation"] =
        value(grade.saturation as f64);
    doc["graphics"]["embedded_effects"]["color_grade"]["vibrance"] = value(grade.vibrance as f64);
    doc["graphics"]["embedded_effects"]["color_grade"]["temperature"] =
        value(grade.temperature as f64);
    doc["graphics"]["embedded_effects"]["color_grade"]["tint"] = value(grade.tint as f64);
    doc["graphics"]["embedded_effects"]["color_grade"]["black_fade"] =
        value(grade.black_fade as f64);
    doc["graphics"]["embedded_effects"]["color_grade"]["highlight_rolloff"] =
        value(grade.highlight_rolloff as f64);
    doc["graphics"]["embedded_effects"]["color_grade"]["lut_enabled"] = value(grade.lut_enabled);
    doc["graphics"]["embedded_effects"]["color_grade"]["lut_file_id"] =
        value(grade.lut_file_id as i64);
    doc["graphics"]["embedded_effects"]["color_grade"]["lut_strength"] =
        value(grade.lut_strength as f64);
    doc["graphics"]["embedded_effects"]["color_grade"]["environment_response"] =
        value(grade.environment_response as f64);
    doc["graphics"]["embedded_effects"]["color_grade"]["deband_enabled"] =
        value(grade.deband_enabled);
    doc["graphics"]["embedded_effects"]["color_grade"]["deband"] = value(grade.deband as f64);
    doc["graphics"]["embedded_effects"]["color_grade"]["film_grain_enabled"] =
        value(grade.film_grain_enabled);
    doc["graphics"]["embedded_effects"]["color_grade"]["film_grain"] =
        value(grade.film_grain as f64);
    doc["graphics"]["embedded_effects"]["color_grade"]["vignette_enabled"] =
        value(grade.vignette_enabled);
    doc["graphics"]["embedded_effects"]["color_grade"]["vignette"] = value(grade.vignette as f64);
    doc["graphics"]["embedded_effects"]["color_grade"]["halation_enabled"] =
        value(grade.halation_enabled);
    doc["graphics"]["embedded_effects"]["color_grade"]["halation"] = value(grade.halation as f64);
    doc["graphics"]["embedded_effects"]["color_grade"]["chromatic_aberration_enabled"] =
        value(grade.chromatic_aberration_enabled);
    doc["graphics"]["embedded_effects"]["color_grade"]["chromatic_aberration"] =
        value(grade.chromatic_aberration as f64);
    doc["graphics"]["embedded_effects"]["color_grade"]["debug_split"] = value(grade.debug_split);
}

#[cfg(test)]
mod tests {
    use super::{
        AtmosphereQuality, BloomingHdrConfig, ColorGradeConfig, EmbeddedEffectsConfig,
        NativePbrConfig, PsychoGraphicsConfig, VolumetricFogConfig, VolumetricLightingConfig,
        save_color_grade_config,
    };
    use toml_edit::DocumentMut;

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

    #[test]
    fn distant_detail_strength_migrates_to_blend_range() {
        let config = NativePbrConfig {
            terrain_lod_noise_scale: 4.0,
            ..NativePbrConfig::default()
        }
        .sanitized();

        assert_eq!(config.terrain_lod_noise_scale, 1.0);
    }

    #[test]
    fn atmosphere_values_are_bounded_on_load() {
        let mut config = EmbeddedEffectsConfig::default();
        config.volumetric_fog.max_distance = f32::INFINITY;
        config.volumetric_fog.scattering_albedo = 4.0;
        config.volumetric_fog.debug_view = 99;
        config.volumetric_lighting.anisotropy = -5.0;
        config.volumetric_lighting.max_distance = f32::INFINITY;
        config.volumetric_lighting.shaft_strength = 9.0;
        config.volumetric_lighting.local_lights_intensity = f32::INFINITY;
        config.volumetric_lighting.debug_view = 99;
        config.volumetric_lighting.temporal_stability = f32::NAN;
        config.blooming_hdr.bloom_intensity = f32::INFINITY;
        config.blooming_hdr.bright_threshold = -5.0;
        config.blooming_hdr.saturation = f32::NAN;
        config.color_grade.exposure = f32::INFINITY;
        config.color_grade.saturation = -3.0;
        config.color_grade.deband = f32::NAN;
        config.color_grade.chromatic_aberration = f32::NAN;
        config.sunshafts.medium_response = f32::NAN;
        config.sunshafts.sun_sample_px = 99;

        let config = config.sanitized();

        assert_eq!(config.volumetric_fog.max_distance, 120_000.0);
        assert_eq!(config.volumetric_fog.scattering_albedo, 1.0);
        assert_eq!(config.volumetric_fog.debug_view, 8);
        assert_eq!(config.volumetric_lighting.anisotropy, -0.8);
        assert_eq!(config.volumetric_lighting.max_distance, 120_000.0);
        assert_eq!(config.volumetric_lighting.shaft_strength, 1.0);
        assert_eq!(config.volumetric_lighting.local_lights_intensity, 1.5);
        assert_eq!(config.volumetric_lighting.debug_view, 8);
        assert_eq!(config.volumetric_lighting.temporal_stability, 0.9);
        assert_eq!(config.blooming_hdr.bloom_intensity, 0.34);
        assert_eq!(config.blooming_hdr.bright_threshold, 0.25);
        assert_eq!(config.blooming_hdr.saturation, 0.92);
        assert_eq!(config.color_grade.exposure, 0.0);
        assert_eq!(config.color_grade.saturation, 0.0);
        assert_eq!(config.color_grade.deband, 0.55);
        assert_eq!(config.color_grade.chromatic_aberration, 0.85);
        assert_eq!(config.sunshafts.medium_response, 1.0);
        assert_eq!(config.sunshafts.sun_sample_px, 48);
    }

    #[test]
    fn every_color_grade_value_is_sanitized_and_legacy_configs_default() {
        let config = ColorGradeConfig {
            enabled: false,
            strength: f32::NAN,
            color_grading_enabled: false,
            exposure: -99.0,
            contrast: 99.0,
            saturation: f32::NAN,
            vibrance: -99.0,
            temperature: f32::INFINITY,
            tint: -99.0,
            black_fade: 99.0,
            highlight_rolloff: f32::NAN,
            lut_enabled: false,
            lut_file_id: 42,
            lut_strength: 99.0,
            environment_response: -99.0,
            deband_enabled: false,
            deband: f32::NAN,
            film_grain_enabled: false,
            film_grain: 99.0,
            vignette_enabled: false,
            vignette: -99.0,
            halation_enabled: false,
            halation: f32::INFINITY,
            chromatic_aberration_enabled: false,
            chromatic_aberration: f32::INFINITY,
            debug_split: true,
        }
        .sanitized();
        assert!(!config.enabled);
        assert_eq!(config.strength, 0.68);
        assert_eq!(config.exposure, -1.5);
        assert_eq!(config.contrast, 0.5);
        assert_eq!(config.saturation, 0.98);
        assert_eq!(config.vibrance, -1.0);
        assert_eq!(config.temperature, 0.015);
        assert_eq!(config.tint, -1.0);
        assert_eq!(config.black_fade, 1.0);
        assert_eq!(config.highlight_rolloff, 0.16);
        assert_eq!(config.lut_file_id, 42);
        assert_eq!(config.lut_strength, 1.0);
        assert_eq!(config.environment_response, 0.0);
        assert_eq!(config.deband, 0.55);
        assert_eq!(config.film_grain, 1.0);
        assert_eq!(config.vignette, 0.0);
        assert_eq!(config.halation, 0.12);
        assert_eq!(config.chromatic_aberration, 0.85);
        assert!(config.debug_split);

        let defaults: ColorGradeConfig = toml::from_str("").expect("legacy color config");
        assert_eq!(defaults.strength, ColorGradeConfig::default().strength);
        assert_eq!(defaults.lut_file_id, 97_154_384);
    }

    #[test]
    fn color_grade_config_round_trips_every_field() {
        let expected = ColorGradeConfig {
            enabled: false,
            strength: 0.11,
            color_grading_enabled: false,
            exposure: -0.22,
            contrast: 0.33,
            saturation: 1.44,
            vibrance: -0.55,
            temperature: 0.66,
            tint: -0.77,
            black_fade: 0.88,
            highlight_rolloff: 0.99,
            lut_enabled: false,
            lut_file_id: 4,
            lut_strength: 0.12,
            environment_response: 0.23,
            deband_enabled: false,
            deband: 0.34,
            film_grain_enabled: false,
            film_grain: 0.45,
            vignette_enabled: false,
            vignette: 0.56,
            halation_enabled: false,
            halation: 0.67,
            chromatic_aberration_enabled: false,
            chromatic_aberration: 0.78,
            debug_split: true,
        };
        let encoded = toml::to_string(&expected).expect("serialize color grade");
        let actual: ColorGradeConfig = toml::from_str(&encoded).expect("deserialize color grade");
        assert_eq!(actual.enabled, expected.enabled);
        assert_eq!(actual.strength, expected.strength);
        assert_eq!(actual.color_grading_enabled, expected.color_grading_enabled);
        assert_eq!(actual.exposure, expected.exposure);
        assert_eq!(actual.contrast, expected.contrast);
        assert_eq!(actual.saturation, expected.saturation);
        assert_eq!(actual.vibrance, expected.vibrance);
        assert_eq!(actual.temperature, expected.temperature);
        assert_eq!(actual.tint, expected.tint);
        assert_eq!(actual.black_fade, expected.black_fade);
        assert_eq!(actual.highlight_rolloff, expected.highlight_rolloff);
        assert_eq!(actual.lut_enabled, expected.lut_enabled);
        assert_eq!(actual.lut_file_id, expected.lut_file_id);
        assert_eq!(actual.lut_strength, expected.lut_strength);
        assert_eq!(actual.environment_response, expected.environment_response);
        assert_eq!(actual.deband_enabled, expected.deband_enabled);
        assert_eq!(actual.deband, expected.deband);
        assert_eq!(actual.film_grain_enabled, expected.film_grain_enabled);
        assert_eq!(actual.film_grain, expected.film_grain);
        assert_eq!(actual.vignette_enabled, expected.vignette_enabled);
        assert_eq!(actual.vignette, expected.vignette);
        assert_eq!(actual.halation_enabled, expected.halation_enabled);
        assert_eq!(actual.halation, expected.halation);
        assert_eq!(
            actual.chromatic_aberration_enabled,
            expected.chromatic_aberration_enabled
        );
        assert_eq!(actual.chromatic_aberration, expected.chromatic_aberration);
        assert_eq!(actual.debug_split, expected.debug_split);
    }

    #[test]
    fn color_grade_disk_document_persists_every_field() {
        let expected = ColorGradeConfig {
            enabled: false,
            strength: 0.11,
            color_grading_enabled: false,
            exposure: -0.22,
            contrast: 0.33,
            saturation: 1.44,
            vibrance: -0.55,
            temperature: 0.66,
            tint: -0.77,
            black_fade: 0.88,
            highlight_rolloff: 0.99,
            lut_enabled: false,
            lut_file_id: 4,
            lut_strength: 0.12,
            environment_response: 0.23,
            deband_enabled: false,
            deband: 0.34,
            film_grain_enabled: false,
            film_grain: 0.45,
            vignette_enabled: false,
            vignette: 0.56,
            halation_enabled: false,
            halation: 0.67,
            chromatic_aberration_enabled: false,
            chromatic_aberration: 0.78,
            debug_split: true,
        };
        let mut document: DocumentMut = "[graphics.embedded_effects.color_grade]\nlut_preset = 4\n"
            .parse()
            .expect("legacy document");
        save_color_grade_config(&mut document, &expected);
        let text = document.to_string();
        let value: toml::Value = toml::from_str(&text).expect("saved TOML value");
        let table = value["graphics"]["embedded_effects"]["color_grade"]
            .as_table()
            .expect("color-grade table");
        assert_eq!(table.len(), 26);
        assert!(!table.contains_key("lut_preset"));

        let decoded: PsychoGraphicsConfig = toml::from_str(&text).expect("saved menu document");
        assert_eq!(
            toml::to_string(&decoded.graphics.embedded_effects.color_grade)
                .expect("serialize decoded grade"),
            toml::to_string(&expected).expect("serialize expected grade")
        );
    }

    #[test]
    fn shipped_color_grade_values_match_rust_defaults() {
        let shipped: PsychoGraphicsConfig =
            toml::from_str(include_str!("../config/omv.toml")).expect("shipped OMV config");
        assert_eq!(
            toml::to_string(&shipped.graphics.embedded_effects.color_grade)
                .expect("serialize shipped grade"),
            toml::to_string(&ColorGradeConfig::default()).expect("serialize default grade")
        );
    }

    #[test]
    fn shipped_bloom_values_match_the_subtle_mojave_tuning_contract() {
        let shipped: PsychoGraphicsConfig =
            toml::from_str(include_str!("../config/omv.toml")).expect("shipped OMV config");
        let actual = shipped.graphics.embedded_effects.blooming_hdr;
        let expected = BloomingHdrConfig::default();
        assert_eq!(actual.bloom_intensity, expected.bloom_intensity);
        assert_eq!(actual.bright_threshold, expected.bright_threshold);
        assert_eq!(actual.radius_pixels, expected.radius_pixels);
        assert_eq!(actual.soft_knee, expected.soft_knee);
        assert_eq!(actual.exposure_bias, expected.exposure_bias);
        assert_eq!(actual.highlight_shoulder, expected.highlight_shoulder);
        assert_eq!(actual.saturation, expected.saturation);
        assert_eq!(actual.warmth, expected.warmth);
        assert_eq!(actual.shadow_lift, expected.shadow_lift);
        assert_eq!(actual.dither, expected.dither);
        assert_eq!(actual.atmosphere, expected.atmosphere);
        assert!(actual.bright_threshold >= 0.60);
        assert!(actual.bloom_intensity <= 0.40);
        assert!((0.85..=1.0).contains(&actual.saturation));
        assert!(actual.warmth <= 0.20);
        assert!(ColorGradeConfig::default().lut_strength <= 0.45);
        assert!(!ColorGradeConfig::default().chromatic_aberration_enabled);
    }

    #[test]
    fn calibrated_fog_default_is_subtle_and_explicit_values_are_preserved() {
        let defaults = VolumetricFogConfig::default();
        assert_eq!(defaults.density, 0.0);
        assert_eq!(defaults.height_density, 0.0000025);

        let mut explicit = defaults;
        explicit.height_density = 0.00002;
        assert_eq!(explicit.sanitized().height_density, 0.00002);

        explicit.height_density = f32::NAN;
        assert_eq!(explicit.sanitized().height_density, 0.0000025);
    }

    #[test]
    fn local_volumetric_light_options_round_trip_and_keep_low_end_quality_explicit() {
        let config = VolumetricLightingConfig {
            local_lights_enabled: false,
            local_lights_intensity: 3.25,
            local_lights_quality: AtmosphereQuality::Performance,
            ..VolumetricLightingConfig::default()
        };
        let encoded = toml::to_string(&config).expect("serialize local volumetric lighting");
        let decoded: VolumetricLightingConfig =
            toml::from_str(&encoded).expect("deserialize local volumetric lighting");
        assert!(!decoded.local_lights_enabled);
        assert_eq!(decoded.local_lights_intensity, 3.25);
        assert_eq!(decoded.local_lights_quality, AtmosphereQuality::Performance);

        let defaults: VolumetricLightingConfig =
            toml::from_str("").expect("legacy config defaults");
        assert!(defaults.local_lights_enabled);
        assert_eq!(defaults.local_lights_intensity, 1.5);
        assert_eq!(defaults.local_lights_quality, AtmosphereQuality::High);
    }
}

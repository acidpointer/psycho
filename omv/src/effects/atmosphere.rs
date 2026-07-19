//! World-only volumetric atmosphere foundation.

use libpsycho::os::windows::directx9::{
    D3DBLEND_ONE, D3DBLENDOP_ADD, D3DCULL_NONE, D3DFMT_A8R8G8B8, D3DFMT_A16B16G16R16F,
    D3DFMT_G16R16F, D3DFORMAT, D3DPOOL_MANAGED, D3DPT_TRIANGLESTRIP, D3DRS_ADAPTIVETESS_Y,
    D3DRS_ALPHABLENDENABLE, D3DRS_ALPHATESTENABLE, D3DRS_BLENDOP, D3DRS_COLORWRITEENABLE,
    D3DRS_CULLMODE, D3DRS_DESTBLEND, D3DRS_MULTISAMPLEANTIALIAS, D3DRS_MULTISAMPLEMASK,
    D3DRS_POINTSIZE, D3DRS_SCISSORTESTENABLE, D3DRS_SRCBLEND, D3DRS_SRGBWRITEENABLE,
    D3DRS_STENCILENABLE, D3DRS_ZENABLE, D3DRS_ZWRITEENABLE, D3DSAMP_ADDRESSU, D3DSAMP_ADDRESSV,
    D3DSAMP_MAGFILTER, D3DSAMP_MINFILTER, D3DSAMP_MIPFILTER, D3DSAMP_SRGBTEXTURE, D3DSURFACE_DESC,
    D3DTA_TEXTURE, D3DTADDRESS_CLAMP, D3DTADDRESS_WRAP, D3DTEXF_LINEAR, D3DTEXF_NONE,
    D3DTEXF_POINT, D3DTOP_SELECTARG1, D3DTSS_ALPHAARG1, D3DTSS_ALPHAOP, D3DTSS_COLORARG1,
    D3DTSS_COLOROP, D3DVIEWPORT9, Device9Ref, Direct3DResult, PixelShader9, ScreenVertex, Surface9,
    Texture9, USAGE_RENDER_TARGET, direct3d_failure,
};

use crate::{
    backend::{AtmosphereFrame, DepthTexture},
    config::{AtmosphereQuality, VolumetricFogConfig, VolumetricLightingConfig},
    shaders::{self, ScreenShaderSource},
};

const COLOR_WRITE_ALL: u32 = 0x0F;
const AMD_ALPHA_TO_COVERAGE_OFF: u32 = u32::from_le_bytes(*b"A2M0");
const MAX_CONTRACT_LOGS: u32 = 32;
const DEPTH_REDUCE_SHADER: &[u8] =
    include_bytes!("../../shaders/embedded/atmosphere_depth_reduce.hlsl");
const INTEGRATE_SHADER: &[u8] = include_bytes!("../../shaders/embedded/atmosphere_integrate.hlsl");
const COMPOSE_SHADER: &[u8] = include_bytes!("../../shaders/embedded/atmosphere_compose.hlsl");
const DEBUG_SHADER: &[u8] = include_bytes!("../../shaders/embedded/atmosphere_debug.hlsl");
const SHAFT_MASK_SHADER: &[u8] =
    include_bytes!("../../shaders/embedded/atmosphere_shaft_mask.hlsl");
const SHAFT_RADIAL_SHADER: &[u8] =
    include_bytes!("../../shaders/embedded/atmosphere_shaft_radial.hlsl");
const LOCAL_LIGHT_SHADER: &[u8] =
    include_bytes!("../../shaders/embedded/atmosphere_local_light.hlsl");
const DENSITY_NOISE_SIZE: u32 = 64;
const DENSITY_NOISE_SEED: u32 = 0xA7F4_31D9;
const LIGHTING_DEBUG_BASE: i32 = 8;
const SHAFT_TARGET_SCALE: u32 = 4;

#[derive(Clone, Copy, Debug)]
pub(crate) struct AtmosphereSettings {
    fog_enabled: bool,
    lighting_enabled: bool,
    density: f32,
    height_density: f32,
    height_falloff: f32,
    base_height: f32,
    pub(crate) max_distance: f32,
    scattering_albedo: f32,
    noise_amount: f32,
    noise_scale: f32,
    noise_speed: f32,
    temporal_stability: f32,
    debug_view: i32,
    quality: AtmosphereQuality,
    lighting_intensity: f32,
    lighting_medium_density: f32,
    anisotropy: f32,
    shaft_strength: f32,
    sun_disk_boost: f32,
    shaft_quality: AtmosphereQuality,
    pub(crate) local_lights_enabled: bool,
    local_lights_intensity: f32,
    local_lights_quality: AtmosphereQuality,
}

impl AtmosphereSettings {
    pub(crate) fn from_config(
        fog: VolumetricFogConfig,
        lighting: VolumetricLightingConfig,
    ) -> Self {
        Self {
            fog_enabled: fog.enabled,
            lighting_enabled: lighting.enabled,
            density: finite(fog.density, 0.0).clamp(0.0, 0.001),
            height_density: finite(fog.height_density, 0.0000025).clamp(0.0, 0.001),
            height_falloff: finite(fog.height_falloff, 0.00008).clamp(0.000001, 0.01),
            base_height: finite(fog.base_height, 0.0).clamp(-100_000.0, 100_000.0),
            max_distance: if fog.enabled {
                finite(fog.max_distance, 120_000.0).clamp(1_000.0, 250_000.0)
            } else {
                finite(lighting.max_distance, 120_000.0).clamp(1_000.0, 250_000.0)
            },
            scattering_albedo: finite(fog.scattering_albedo, 0.88).clamp(0.0, 1.0),
            noise_amount: finite(fog.noise_amount, 0.18).clamp(0.0, 1.0),
            noise_scale: finite(fog.noise_scale, 0.00035).clamp(0.000001, 0.05),
            noise_speed: finite(fog.noise_speed, 0.02).clamp(0.0, 1.0),
            temporal_stability: finite(fog.temporal_stability, 0.9).clamp(0.0, 0.98),
            debug_view: selected_debug_view(fog.debug_view, lighting.debug_view),
            quality: if fog.enabled {
                fog.quality
            } else {
                lighting.shaft_quality
            },
            lighting_intensity: finite(lighting.intensity, 0.95).clamp(0.0, 8.0),
            lighting_medium_density: finite(lighting.medium_density, 0.0000025).clamp(0.0, 0.001),
            anisotropy: finite(lighting.anisotropy, 0.58).clamp(-0.8, 0.9),
            shaft_strength: finite(lighting.shaft_strength, 0.72).clamp(0.0, 1.0),
            sun_disk_boost: finite(lighting.sun_disk_boost, 1.0).clamp(0.0, 8.0),
            shaft_quality: lighting.shaft_quality,
            local_lights_enabled: lighting.local_lights_enabled,
            local_lights_intensity: finite(lighting.local_lights_intensity, 1.5).clamp(0.0, 4.0),
            local_lights_quality: lighting.local_lights_quality,
        }
    }

    pub(crate) fn from_sources(
        fog: Option<&ScreenShaderSource>,
        lighting: Option<&ScreenShaderSource>,
    ) -> Self {
        let fog_constants = fog.map(|source| source.option_constants.as_slice());
        let lighting_constants = lighting.map(|source| source.option_constants.as_slice());
        let fog_enabled = fog.is_some();
        let lighting_enabled = lighting.is_some();
        let density = option_component(fog_constants, 0, 0, 0.0);
        let height_density = option_component(fog_constants, 0, 1, 0.0000025);
        let height_falloff = option_component(fog_constants, 0, 2, 0.00008);
        let base_height = option_component(fog_constants, 0, 3, 0.0);
        let max_distance = option_component(fog_constants, 1, 0, 120_000.0);
        let scattering_albedo = option_component(fog_constants, 1, 1, 0.88);
        let noise_amount = option_component(fog_constants, 1, 2, 0.18);
        let noise_scale = option_component(fog_constants, 1, 3, 0.00035);
        let noise_speed = option_component(fog_constants, 2, 0, 0.02);
        let temporal_stability = option_component(fog_constants, 2, 1, 0.9);
        let fog_debug = fog_constants
            .and_then(|constants| constants.get(2))
            .map_or(0, |value| finite_i32(value[3]));
        let lighting_intensity = option_component(lighting_constants, 0, 0, 0.95);
        let lighting_medium_density = option_component(lighting_constants, 0, 1, 0.0000025);
        let lighting_max_distance = option_component(lighting_constants, 0, 2, 120_000.0);
        let anisotropy = option_component(lighting_constants, 0, 3, 0.58);
        let shaft_strength = option_component(lighting_constants, 1, 0, 0.72);
        let sun_disk_boost = option_component(lighting_constants, 1, 1, 1.0);
        let lighting_debug = lighting_constants
            .and_then(|constants| constants.get(2))
            .map_or(0, |value| finite_i32(value[3]));
        let fog_quality = fog_constants
            .and_then(|constants| constants.get(2))
            .map(|value| AtmosphereQuality::from_index(finite_i32(value[2])));
        let lighting_quality = lighting_constants
            .and_then(|constants| constants.get(1))
            .map(|value| AtmosphereQuality::from_index(finite_i32(value[2])));
        let local_lights_enabled = lighting_constants
            .and_then(|constants| constants.get(2))
            .is_some_and(|value| value[0] >= 0.5);
        let local_lights_intensity = option_component(lighting_constants, 2, 1, 1.5);
        let local_lights_quality = lighting_constants
            .and_then(|constants| constants.get(2))
            .map_or(AtmosphereQuality::High, |value| {
                AtmosphereQuality::from_index(finite_i32(value[2]))
            });
        let quality = fog_quality.or(lighting_quality).unwrap_or_default();

        Self {
            fog_enabled,
            lighting_enabled,
            density: finite(density, 0.0).clamp(0.0, 0.001),
            height_density: finite(height_density, 0.0000025).clamp(0.0, 0.001),
            height_falloff: finite(height_falloff, 0.00008).clamp(0.000001, 0.01),
            base_height: finite(base_height, 0.0).clamp(-100_000.0, 100_000.0),
            max_distance: if fog_enabled {
                finite(max_distance, 120_000.0).clamp(1_000.0, 250_000.0)
            } else {
                finite(lighting_max_distance, 120_000.0).clamp(1_000.0, 250_000.0)
            },
            scattering_albedo: finite(scattering_albedo, 0.88).clamp(0.0, 1.0),
            noise_amount: finite(noise_amount, 0.18).clamp(0.0, 1.0),
            noise_scale: finite(noise_scale, 0.00035).clamp(0.000001, 0.05),
            noise_speed: finite(noise_speed, 0.02).clamp(0.0, 1.0),
            temporal_stability: finite(temporal_stability, 0.9).clamp(0.0, 0.98),
            debug_view: selected_debug_view(fog_debug, lighting_debug),
            quality,
            lighting_intensity: finite(lighting_intensity, 0.95).clamp(0.0, 8.0),
            lighting_medium_density: finite(lighting_medium_density, 0.0000025).clamp(0.0, 0.001),
            anisotropy: finite(anisotropy, 0.58).clamp(-0.8, 0.9),
            shaft_strength: finite(shaft_strength, 0.72).clamp(0.0, 1.0),
            sun_disk_boost: finite(sun_disk_boost, 1.0).clamp(0.0, 8.0),
            shaft_quality: lighting_quality.unwrap_or_default(),
            local_lights_enabled,
            local_lights_intensity: finite(local_lights_intensity, 1.5).clamp(0.0, 4.0),
            local_lights_quality,
        }
    }

    pub(crate) fn requires_world_color(self) -> bool {
        self.requires_integration() || self.debug_view != 0
    }

    pub(crate) fn requires_depth(self) -> bool {
        self.requires_integration() || self.debug_view != 0
    }

    pub(crate) fn requires_integration(self) -> bool {
        (self.fog_enabled && (self.density > 0.0 || self.height_density > 0.0))
            || (self.lighting_enabled && self.lighting_medium_density > 0.0)
            || (self.local_lights_enabled
                && self.local_lights_intensity > 0.0
                && self.lighting_medium_density > 0.0)
    }

    pub(crate) fn estimated_horizontal_transmittance(self, frame: AtmosphereFrame) -> f32 {
        if !self.fog_enabled {
            return (-(self.lighting_medium_density) * frame.distance_bound)
                .exp()
                .clamp(0.0, 1.0);
        }
        let camera_height = frame.camera.world_transform.translation[2];
        let height_density = self.height_density
            * (-(camera_height - self.base_height) * self.height_falloff)
                .exp()
                .clamp(0.0, 64.0);
        (-(self.density + height_density) * frame.distance_bound)
            .exp()
            .clamp(0.0, 1.0)
    }

    fn target_scale(self) -> u32 {
        let quality = if self.local_lights_enabled
            && self.local_lights_quality.index() > self.quality.index()
        {
            self.local_lights_quality
        } else {
            self.quality
        };
        match quality {
            AtmosphereQuality::Performance => 4,
            AtmosphereQuality::High | AtmosphereQuality::Ultra => 2,
        }
    }

    fn sample_count(self) -> u32 {
        match self.quality {
            AtmosphereQuality::Performance => 8,
            AtmosphereQuality::High => 12,
            AtmosphereQuality::Ultra => 20,
        }
    }

    fn shader_index(self) -> usize {
        self.quality.index() as usize
    }

    fn shaft_sample_count(self) -> u32 {
        match self.shaft_quality {
            AtmosphereQuality::Performance => 24,
            AtmosphereQuality::High => 40,
            AtmosphereQuality::Ultra => 56,
        }
    }

    fn shaft_shader_index(self) -> usize {
        self.shaft_quality.index() as usize
    }

    fn local_sample_count(self) -> u32 {
        match self.local_lights_quality {
            AtmosphereQuality::Performance => 4,
            AtmosphereQuality::High => 6,
            AtmosphereQuality::Ultra => 10,
        }
    }

    fn local_max_lights(self) -> usize {
        match self.local_lights_quality {
            AtmosphereQuality::Performance => 2,
            AtmosphereQuality::High | AtmosphereQuality::Ultra => 4,
        }
    }

    fn local_shader_index(self) -> usize {
        self.local_lights_quality.index() as usize
    }

    fn lighting_debug_view(self) -> i32 {
        (self.debug_view - LIGHTING_DEBUG_BASE).max(0)
    }

    fn fog_debug_view(self) -> i32 {
        if self.debug_view <= LIGHTING_DEBUG_BASE {
            self.debug_view
        } else {
            0
        }
    }

    fn effective_uniform_density(self, fog_active: bool) -> f32 {
        if fog_active {
            self.density
        } else {
            self.lighting_medium_density
        }
    }

    fn effective_scattering_albedo(self, fog_active: bool) -> f32 {
        if fog_active {
            self.scattering_albedo
        } else {
            1.0
        }
    }
}

fn selected_debug_view(fog: i32, lighting: i32) -> i32 {
    let lighting = lighting.clamp(0, 8);
    if lighting != 0 {
        LIGHTING_DEBUG_BASE + lighting
    } else {
        fog.clamp(0, LIGHTING_DEBUG_BASE)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AtmosphereSourceTransfer {
    ExtendedSrgb,
}

impl AtmosphereSourceTransfer {
    const fn label(self) -> &'static str {
        match self {
            Self::ExtendedSrgb => "extended-srgb",
        }
    }
}

const SOURCE_TRANSFER: AtmosphereSourceTransfer = AtmosphereSourceTransfer::ExtendedSrgb;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FogIntegrationGate {
    Disabled,
    EmptyMedium,
    MissingDepthContract,
    MissingWorldTransform,
    ExteriorUnknown,
    Interior,
    UnderwaterUnknown,
    Underwater,
    NoReadyContribution,
    Ready,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FogCompositionGate {
    DebugView,
    IntegrationUnavailable,
    MissingWorldColor,
    UnsupportedWorldTarget,
    TaaAlphaUnavailable,
    Ready,
}

impl FogCompositionGate {
    fn label(self) -> &'static str {
        match self {
            Self::DebugView => "debug_view",
            Self::IntegrationUnavailable => "integration_unavailable",
            Self::MissingWorldColor => "missing_world_color",
            Self::UnsupportedWorldTarget => "unsupported_world_target",
            Self::TaaAlphaUnavailable => "taa_alpha_unavailable",
            Self::Ready => "ready",
        }
    }
}

impl FogIntegrationGate {
    fn label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::EmptyMedium => "empty_medium",
            Self::MissingDepthContract => "missing_depth_contract",
            Self::MissingWorldTransform => "missing_world_transform",
            Self::ExteriorUnknown => "exterior_unknown",
            Self::Interior => "interior",
            Self::UnderwaterUnknown => "underwater_unknown",
            Self::Underwater => "underwater",
            Self::NoReadyContribution => "no_ready_contribution",
            Self::Ready => "ready",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct MediumColor {
    linear_rgb: [f32; 3],
}

#[derive(Clone, Copy, Debug)]
struct DirectionalLight {
    world_direction: [f32; 3],
    linear_color: [f32; 3],
    linear_disk_delta: [f32; 3],
    daylight: f32,
    projection: crate::backend::SunProjectionFrame,
}

#[derive(Clone, Copy, Debug)]
struct AtmosphereContributions {
    medium_color: [f32; 3],
    fog: bool,
    light: Option<DirectionalLight>,
}

impl AtmosphereContributions {
    fn any(self) -> bool {
        self.fog || self.light.is_some()
    }

    fn lighting_ready(self) -> bool {
        self.light.is_some()
    }
}

#[cfg(test)]
fn henyey_greenstein(mu: f32, anisotropy: f32) -> f32 {
    let mu = finite(mu, 0.0).clamp(-1.0, 1.0);
    let g = finite(anisotropy, 0.0).clamp(-0.8, 0.9);
    let denominator = (1.0 + g * g - 2.0 * g * mu).max(0.000001);
    (1.0 - g * g) / (4.0 * core::f32::consts::PI * denominator.powf(1.5))
}

#[cfg(test)]
fn directional_phase_response(mu: f32, anisotropy: f32) -> f32 {
    henyey_greenstein(mu, anisotropy) * 4.0 * core::f32::consts::PI
}

#[cfg(test)]
fn directional_scatter_amount(
    medium_transmittance: f32,
    scattering_albedo: f32,
    lighting_density: f32,
    distance: f32,
) -> f32 {
    let fog_amount = (1.0 - finite(medium_transmittance, 1.0).clamp(0.0, 1.0))
        * finite(scattering_albedo, 0.0).clamp(0.0, 1.0);
    let lighting_optical_depth =
        (finite(lighting_density, 0.0).max(0.0) * finite(distance, 0.0).max(0.0)).clamp(0.0, 40.0);
    fog_amount.max(1.0 - (-lighting_optical_depth).exp())
}

#[cfg(test)]
fn bounded_shaft_visibility(field: f32, edge_fade: f32, strength: f32) -> f32 {
    let field = finite(field, 1.0).clamp(0.0, 1.0);
    let influence = finite(edge_fade, 0.0).clamp(0.0, 1.0) * finite(strength, 0.0).clamp(0.0, 1.0);
    1.0 + (field - 1.0) * influence
}

#[cfg(test)]
fn shaft_visibility_from_blocked_fraction(
    blocked_fraction: f32,
    edge_fade: f32,
    strength: f32,
) -> f32 {
    let field = (-12.0 * finite(blocked_fraction, 0.0).clamp(0.0, 1.0)).exp();
    bounded_shaft_visibility(field, edge_fade, strength)
}

#[cfg(test)]
fn directional_radiance(
    base: [f32; 3],
    disk_delta: [f32; 3],
    disk_boost: f32,
    mu: f32,
) -> [f32; 3] {
    let disk_lobe = smooth01(((finite(mu, 0.0) - 0.995) / (0.9999 - 0.995)).clamp(0.0, 1.0));
    let boost = finite(disk_boost, 0.0).clamp(0.0, 8.0) * disk_lobe;
    [
        finite(base[0], 0.0).max(0.0) + finite(disk_delta[0], 0.0).max(0.0) * boost,
        finite(base[1], 0.0).max(0.0) + finite(disk_delta[1], 0.0).max(0.0) * boost,
        finite(base[2], 0.0).max(0.0) + finite(disk_delta[2], 0.0).max(0.0) * boost,
    ]
}

fn project_sun_from_captured_camera(
    camera: crate::backend::CameraFrame,
    world_direction: [f32; 3],
) -> crate::backend::SunProjectionFrame {
    crate::backend::project_world_direction(camera, world_direction)
}

#[cfg(test)]
fn smooth01(value: f32) -> f32 {
    let value = finite(value, 0.0).clamp(0.0, 1.0);
    value * value * (3.0 - 2.0 * value)
}

fn dot3(a: [f32; 3], b: [f32; 3]) -> f32 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

#[cfg(test)]
fn ray_sphere_interval(
    origin: [f32; 3],
    direction: [f32; 3],
    center: [f32; 3],
    radius: f32,
    depth_distance: f32,
    max_distance: f32,
) -> Option<(f32, f32)> {
    if !origin.into_iter().all(f32::is_finite)
        || !direction.into_iter().all(f32::is_finite)
        || !center.into_iter().all(f32::is_finite)
        || !radius.is_finite()
        || radius <= 0.0
    {
        return None;
    }
    let to_center = [
        center[0] - origin[0],
        center[1] - origin[1],
        center[2] - origin[2],
    ];
    let projected_center = dot3(to_center, direction);
    let discriminant =
        projected_center * projected_center - (dot3(to_center, to_center) - radius * radius);
    if !discriminant.is_finite() || discriminant <= 0.0 {
        return None;
    }
    let root = discriminant.sqrt();
    let entry = (projected_center - root).max(0.0);
    let exit = (projected_center + root)
        .min(depth_distance)
        .min(max_distance);
    (exit - entry > 0.0001).then_some((entry, exit))
}

#[cfg(test)]
fn project_native_shadow(matrix: [[f32; 4]; 4], position: [f32; 3]) -> Option<([f32; 2], f32)> {
    let homogeneous = [position[0], position[1], position[2], 1.0];
    let shadow = matrix.map(|row| {
        row[0] * homogeneous[0] + row[1] * homogeneous[1] + row[2] * homogeneous[2] + row[3]
    });
    if !shadow.into_iter().all(f32::is_finite) || shadow[3] <= 0.000001 {
        return None;
    }
    let uv = [
        0.5 * shadow[0] / shadow[3] + 0.5,
        0.5 - 0.5 * shadow[1] / shadow[3],
    ];
    (uv.into_iter()
        .all(|value| value.is_finite() && (0.0..=1.0).contains(&value)))
    .then_some((uv, shadow[2]))
}

#[cfg(test)]
fn integrated_uniform_scatter(density: f32, distance: f32, samples: u32) -> f32 {
    let step = distance / samples.max(1) as f32;
    let step_transmittance = (-density.max(0.0) * step).exp();
    let mut transmittance = 1.0;
    let mut result = 0.0;
    for _ in 0..samples.max(1) {
        result += transmittance * (1.0 - step_transmittance);
        transmittance *= step_transmittance;
    }
    result
}

pub(crate) struct AtmosphereEffect {
    depth_reduce_half_shader: PixelShader9,
    depth_reduce_quarter_shader: PixelShader9,
    shaft_pipeline: Option<ShaftPipeline>,
    local_light_pipeline: Option<LocalLightPipeline>,
    integrate_shaders: [PixelShader9; 3],
    compose_shader: PixelShader9,
    debug_shader: PixelShader9,
    density_noise: Texture9,
    neutral_visibility: Texture9,
    targets: Option<AtmosphereTargets>,
    shaft_targets: Option<ShaftTargets>,
    failed_target_size: Option<(u32, u32, u32)>,
    failed_shaft_size: Option<(u32, u32)>,
    last_contract: Option<u16>,
    last_fog_signature: Option<[i32; 6]>,
    contract_logs: u32,
    last_integration_gate: Option<FogIntegrationGate>,
    integration_gate_logs: u32,
    last_composition_gate: Option<FogCompositionGate>,
    composition_gate_logs: u32,
    integration_draws: u64,
    shaft_draws: u64,
    local_light_draws: u64,
    composition_draws: u64,
    debug_draws: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AtmosphereDrawOutcome {
    Skipped,
    NoVisibleContribution,
    Composed,
    ComposedWithLighting,
    DebugDrawn,
    LightingDebugDrawn,
}

impl AtmosphereDrawOutcome {
    pub(crate) fn drew(self) -> bool {
        matches!(
            self,
            Self::Composed
                | Self::ComposedWithLighting
                | Self::DebugDrawn
                | Self::LightingDebugDrawn
        )
    }

    pub(crate) fn completes_pre_alpha(self) -> bool {
        self.drew() || self == Self::NoVisibleContribution
    }
}

impl AtmosphereEffect {
    pub(crate) fn create(device: &Device9Ref<'_>) -> Direct3DResult<Self> {
        device
            .direct3d()?
            .check_default_render_target_texture_support(D3DFMT_G16R16F)?;
        device
            .direct3d()?
            .check_default_render_target_texture_support(D3DFMT_A16B16G16R16F)?;
        let quarter_source = depth_reduce_shader_source(4);
        let shaft_pipeline = match ShaftPipeline::create(device) {
            Ok(pipeline) => Some(pipeline),
            Err(err) => {
                log::warn!(
                    "[ATMOSPHERE] Optional shaft pipeline unavailable; base directional scattering remains active: {err}"
                );
                None
            }
        };
        let local_light_pipeline = match LocalLightPipeline::create(device) {
            Ok(pipeline) => Some(pipeline),
            Err(err) => {
                log::warn!(
                    "[ATMOSPHERE LOCAL] Optional FP16 additive pipeline unavailable; fog and directional lighting remain active: {err}"
                );
                None
            }
        };
        Ok(Self {
            depth_reduce_half_shader: compile_shader(
                device,
                "atmosphere_depth_reduce.hlsl:half",
                DEPTH_REDUCE_SHADER,
            )?,
            depth_reduce_quarter_shader: compile_shader(
                device,
                "atmosphere_depth_reduce.hlsl:quarter",
                &quarter_source,
            )?,
            shaft_pipeline,
            local_light_pipeline,
            integrate_shaders: [
                compile_shader(
                    device,
                    "atmosphere_integrate.hlsl:performance",
                    &integration_shader_source(8),
                )?,
                compile_shader(
                    device,
                    "atmosphere_integrate.hlsl:high",
                    &integration_shader_source(12),
                )?,
                compile_shader(
                    device,
                    "atmosphere_integrate.hlsl:ultra",
                    &integration_shader_source(20),
                )?,
            ],
            compose_shader: compile_shader(device, "atmosphere_compose.hlsl", COMPOSE_SHADER)?,
            debug_shader: compile_shader(device, "atmosphere_debug.hlsl", DEBUG_SHADER)?,
            density_noise: create_density_noise(device)?,
            neutral_visibility: create_neutral_visibility(device)?,
            targets: None,
            shaft_targets: None,
            failed_target_size: None,
            failed_shaft_size: None,
            last_contract: None,
            last_fog_signature: None,
            contract_logs: 0,
            last_integration_gate: None,
            integration_gate_logs: 0,
            last_composition_gate: None,
            composition_gate_logs: 0,
            integration_draws: 0,
            shaft_draws: 0,
            local_light_draws: 0,
            composition_draws: 0,
            debug_draws: 0,
        })
    }

    pub(crate) fn draw(
        &mut self,
        device: &Device9Ref<'_>,
        world_target: &Surface9,
        desc: &D3DSURFACE_DESC,
        frame: AtmosphereFrame,
        world_color: Option<&Texture9>,
        settings: AtmosphereSettings,
        taa_enabled: bool,
        taa_alpha_ready: bool,
        local_epoch: Option<&crate::fnv_local_lights::LocalLightEpoch>,
    ) -> Direct3DResult<AtmosphereDrawOutcome> {
        self.log_contract(
            desc,
            frame,
            world_color.is_some(),
            taa_enabled,
            taa_alpha_ready,
        );
        let mut usable_local_lights = [None; 4];
        let mut usable_local_count = 0usize;
        let mut captured_local_count = 0usize;
        let mut captured_local_age = 0u32;
        if settings.local_lights_enabled
            && settings.local_lights_intensity > 0.0
            && self.local_light_pipeline.is_some()
            && frame.material_state.exterior_known
            && frame.underwater_contract_ready()
            && !frame.underwater.underwater
            && let Some(epoch) = local_epoch
            && epoch.device_identity == device.as_raw() as usize
        {
            captured_local_count = epoch.light_count();
            captured_local_age = crate::hooks::render_epoch().wrapping_sub(epoch.render_epoch);
            for light in epoch.lights() {
                if usable_local_count >= settings.local_max_lights() {
                    break;
                }
                if local_light_scissor(
                    frame.camera,
                    desc.Width,
                    desc.Height,
                    light.values.position,
                    light.values.radius,
                    settings.max_distance,
                )
                .is_none()
                {
                    continue;
                }
                usable_local_lights[usable_local_count] = Some(UsableLocalLight {
                    light,
                    shadow: light.shadow_binding(device.as_raw() as usize),
                });
                usable_local_count += 1;
            }
        }
        let local_ready = usable_local_count != 0;
        let integration_gate = fog_integration_gate(frame, settings, local_ready);
        self.log_integration_gate(integration_gate, settings);
        if settings.debug_view == 0
            && matches!(
                integration_gate,
                FogIntegrationGate::Disabled
                    | FogIntegrationGate::EmptyMedium
                    | FogIntegrationGate::Interior
                    | FogIntegrationGate::Underwater
                    | FogIntegrationGate::NoReadyContribution
            )
        {
            return Ok(AtmosphereDrawOutcome::NoVisibleContribution);
        }
        let Some(depth) = frame.depth.texture else {
            return Ok(AtmosphereDrawOutcome::Skipped);
        };
        if !frame.camera.available
            || frame.depth.world_projection.reversed_depth.is_none()
            || !frame.distance_bound.is_finite()
            || frame.distance_bound <= frame.camera.near_z
        {
            return Ok(AtmosphereDrawOutcome::Skipped);
        }

        self.ensure_targets(device, desc, settings.target_scale())?;
        let contributions = resolve_contributions(frame, settings);
        let shaft_requested = contributions.light.is_some_and(|light| {
            light.projection.facing > 0.001
                && light.projection.on_screen
                && light.projection.edge_fade > 0.0
                && (settings.shaft_strength > 0.0
                    || matches!(settings.lighting_debug_view(), 1 | 2))
        });
        if shaft_requested && self.shaft_pipeline.is_some() {
            self.ensure_shaft_targets(device, desc);
        }
        let Some(targets) = self.targets.as_ref() else {
            return Ok(AtmosphereDrawOutcome::Skipped);
        };

        bind_pipeline_state(device)?;
        draw_depth_reduce(
            device,
            if targets.scale == 4 {
                &self.depth_reduce_quarter_shader
            } else {
                &self.depth_reduce_half_shader
            },
            targets,
            desc,
            frame,
            depth,
        )?;
        let shaft_ready = if shaft_requested {
            if let (Some(shaft_targets), Some(light), Some(pipeline)) = (
                self.shaft_targets.as_ref(),
                contributions.light,
                self.shaft_pipeline.as_ref(),
            ) {
                draw_shaft_mask(device, &pipeline.mask_shader, targets, shaft_targets, frame)?;
                draw_shaft_radial(
                    device,
                    &pipeline.radial_shaders[settings.shaft_shader_index()],
                    shaft_targets,
                    light,
                    settings,
                )?;
                self.shaft_draws = self.shaft_draws.saturating_add(2);
                true
            } else {
                false
            }
        } else {
            false
        };
        let integration_ready = if integration_gate == FogIntegrationGate::Ready {
            let shaft_visibility = self
                .shaft_targets
                .as_ref()
                .filter(|_| shaft_ready)
                .map_or(&self.neutral_visibility, |targets| &targets.radial.texture);
            draw_integration(
                device,
                &self.integrate_shaders[settings.shader_index()],
                targets,
                &self.density_noise,
                shaft_visibility,
                frame,
                settings,
                contributions,
                shaft_ready,
                false,
            )?;
            draw_integration(
                device,
                &self.integrate_shaders[settings.shader_index()],
                targets,
                &self.density_noise,
                shaft_visibility,
                frame,
                settings,
                contributions,
                shaft_ready,
                true,
            )?;
            self.integration_draws = self.integration_draws.saturating_add(1);
            if self.integration_draws == 1 {
                log::info!(
                    "[ATMOSPHERE] Layered integration active: fog={}, lighting={}, quality={:?}, scale={}, density_samples={}, shaft_samples={}, target={}x{} near/far=A16B16G16R16F",
                    contributions.fog,
                    contributions.lighting_ready(),
                    settings.quality,
                    settings.target_scale(),
                    settings.sample_count(),
                    settings.shaft_sample_count(),
                    targets.width,
                    targets.height,
                );
            }
            if local_ready && let Some(local_pipeline) = self.local_light_pipeline.as_ref() {
                let local_stats = draw_local_lights(
                    device,
                    local_pipeline,
                    targets,
                    &self.density_noise,
                    frame,
                    settings,
                    &usable_local_lights,
                )?;
                bind_pipeline_state(device)?;
                self.local_light_draws = self
                    .local_light_draws
                    .saturating_add(local_stats.draws as u64);
                crate::fnv_local_lights::record_rendered_lights(local_stats.lights);
                if local_stats.draws != 0 && self.local_light_draws == local_stats.draws as u64 {
                    log::info!(
                        "[ATMOSPHERE LOCAL] Scissored scene-wide integration active: quality={:?}, scale={}, samples={}, captured={}, usable={}, shadowed={}, capture_age={}, max_lights={}, draw_ceiling={}",
                        settings.local_lights_quality,
                        targets.scale,
                        settings.local_sample_count(),
                        captured_local_count,
                        usable_local_count,
                        usable_local_lights
                            .iter()
                            .flatten()
                            .filter(|light| light.shadow.is_some())
                            .count(),
                        captured_local_age,
                        settings.local_max_lights(),
                        local_light_draw_count(
                            usable_local_lights
                                .iter()
                                .flatten()
                                .filter(|light| light.shadow.is_none())
                                .count(),
                            usable_local_lights
                                .iter()
                                .flatten()
                                .filter(|light| light.shadow.is_some())
                                .count(),
                        ),
                    );
                }
            }
            true
        } else {
            false
        };
        let composition_gate = fog_composition_gate(
            integration_gate,
            integration_ready,
            world_color.is_some(),
            desc,
            settings,
            taa_enabled,
            taa_alpha_ready,
        );
        log_composition_gate(
            &mut self.last_composition_gate,
            &mut self.composition_gate_logs,
            composition_gate,
            self.integration_draws,
            self.composition_draws,
            self.debug_draws,
        );

        let local_debug = settings.lighting_debug_view() >= 6;
        if settings.debug_view == 0 || local_debug {
            if composition_gate != FogCompositionGate::Ready {
                return Ok(AtmosphereDrawOutcome::Skipped);
            }
            let Some(world_color) = world_color else {
                return Ok(AtmosphereDrawOutcome::Skipped);
            };
            draw_composition(
                device,
                &self.compose_shader,
                world_target,
                desc,
                targets,
                world_color,
                depth,
                frame,
                false,
            )?;
            self.composition_draws = self.composition_draws.saturating_add(1);
            if self.composition_draws == 1 {
                log::info!(
                    "[ATMOSPHERE] Production composition active: fog={}, lighting={}, quality={:?}, scale={}, target={}x{} format=0x{:08X}, transfer={}",
                    contributions.fog,
                    contributions.lighting_ready(),
                    settings.quality,
                    settings.target_scale(),
                    desc.Width,
                    desc.Height,
                    desc.Format.0,
                    SOURCE_TRANSFER.label(),
                );
            }
            return Ok(if contributions.lighting_ready() || local_ready {
                AtmosphereDrawOutcome::ComposedWithLighting
            } else {
                AtmosphereDrawOutcome::Composed
            });
        }
        if (settings.fog_debug_view() >= 6 || settings.lighting_debug_view() >= 3)
            && !integration_ready
        {
            return Ok(AtmosphereDrawOutcome::Skipped);
        }
        let Some(world_color) = world_color else {
            return Ok(AtmosphereDrawOutcome::Skipped);
        };
        if settings.fog_debug_view() == 8 {
            draw_composition(
                device,
                &self.compose_shader,
                world_target,
                desc,
                targets,
                world_color,
                depth,
                frame,
                true,
            )?;
        } else {
            draw_debug(
                device,
                &self.debug_shader,
                world_target,
                desc,
                targets,
                world_color,
                frame,
                settings.debug_view,
                integration_ready,
                settings,
                contributions,
                shaft_ready,
                self.shaft_targets.as_ref(),
                &self.neutral_visibility,
            )?;
        }
        self.debug_draws = self.debug_draws.saturating_add(1);
        Ok(if settings.lighting_debug_view() != 0 {
            AtmosphereDrawOutcome::LightingDebugDrawn
        } else {
            AtmosphereDrawOutcome::DebugDrawn
        })
    }

    fn ensure_targets(
        &mut self,
        device: &Device9Ref<'_>,
        desc: &D3DSURFACE_DESC,
        target_scale: u32,
    ) -> Direct3DResult<()> {
        let size = (desc.Width, desc.Height, target_scale);
        let needs_targets = self
            .targets
            .as_ref()
            .is_none_or(|targets| !targets.matches(desc.Width, desc.Height, target_scale));
        if !needs_targets || self.failed_target_size == Some(size) {
            return Ok(());
        }

        match AtmosphereTargets::create(device, desc.Width, desc.Height, target_scale) {
            Ok(targets) => {
                log::info!(
                    "[ATMOSPHERE] Targets: full={}x{}, reduced={}x{}, scale={}, depth=G16R16F, near/far=A16B16G16R16F",
                    desc.Width,
                    desc.Height,
                    targets.width,
                    targets.height,
                    targets.scale,
                );
                self.targets = Some(targets);
                self.failed_target_size = None;
                Ok(())
            }
            Err(err) => {
                self.targets = None;
                self.failed_target_size = Some(size);
                Err(err)
            }
        }
    }

    fn ensure_shaft_targets(&mut self, device: &Device9Ref<'_>, desc: &D3DSURFACE_DESC) {
        let size = (
            desc.Width.div_ceil(SHAFT_TARGET_SCALE).max(1),
            desc.Height.div_ceil(SHAFT_TARGET_SCALE).max(1),
        );
        let needs_targets = self
            .shaft_targets
            .as_ref()
            .is_none_or(|targets| !targets.matches(size.0, size.1));
        if !needs_targets || self.failed_shaft_size == Some(size) {
            return;
        }
        match ShaftTargets::create(device, size.0, size.1) {
            Ok(targets) => {
                log::info!(
                    "[ATMOSPHERE] Shaft targets: {}x{} G16R16F mask/visibility",
                    targets.width,
                    targets.height,
                );
                self.shaft_targets = Some(targets);
                self.failed_shaft_size = None;
            }
            Err(err) => {
                self.shaft_targets = None;
                self.failed_shaft_size = Some(size);
                log::warn!(
                    "[ATMOSPHERE] Optional shaft targets unavailable at {}x{}: {err}",
                    size.0,
                    size.1,
                );
            }
        }
    }

    fn log_contract(
        &mut self,
        desc: &D3DSURFACE_DESC,
        frame: AtmosphereFrame,
        world_color: bool,
        taa_enabled: bool,
        taa_alpha_ready: bool,
    ) {
        let underwater_epoch_matches = frame.underwater_contract_ready();
        let contract = (frame.depth.texture.is_some() as u16)
            | ((frame.camera.available as u16) << 1)
            | ((frame.depth.world_projection.reversed_depth.is_some() as u16) << 2)
            | ((frame.environment.fog_available as u16) << 3)
            | ((frame.sky.is_some() as u16) << 4)
            | ((frame.sun.available as u16) << 5)
            | ((frame.material_state.exterior_known as u16) << 6)
            | ((frame.material_state.is_exterior as u16) << 7)
            | ((world_color as u16) << 8)
            | ((frame.underwater.hook_available as u16) << 9)
            | ((underwater_epoch_matches as u16) << 10)
            | ((frame.underwater.underwater as u16) << 11)
            | ((frame.camera.world_transform.available as u16) << 12)
            | ((taa_enabled as u16) << 13)
            | ((taa_alpha_ready as u16) << 14);
        let fog = frame.environment;
        let fog_signature = [
            quantize(fog.fog_color[0], 64.0),
            quantize(fog.fog_color[1], 64.0),
            quantize(fog.fog_color[2], 64.0),
            quantize(fog.fog_start, 0.01),
            quantize(fog.fog_end, 0.01),
            quantize(fog.fog_power, 64.0),
        ];
        if (self.last_contract == Some(contract) && self.last_fog_signature == Some(fog_signature))
            || self.contract_logs >= MAX_CONTRACT_LOGS
        {
            return;
        }

        self.last_contract = Some(contract);
        self.last_fog_signature = Some(fog_signature);
        self.contract_logs += 1;
        log::info!(
            "[ATMOSPHERE] Contract: target={}x{} format=0x{:08X} usage=0x{:08X} multisample={:?}/{}, transfer={}, epoch={}, depth={}, camera={} transform={}, reversed={:?}, world_color={}, TAA={}/alpha_history={}, fog={} rgb=({:.4},{:.4},{:.4}) range=({:.2},{:.2}) power={:.4}, sky={}, sun={}, exterior={:?}, underwater_hook={} underwater={:?} underwater_epoch={}, distance_bound={:.2}",
            desc.Width,
            desc.Height,
            desc.Format.0,
            desc.Usage,
            desc.MultiSampleType,
            desc.MultiSampleQuality,
            SOURCE_TRANSFER.label(),
            frame.frame_epoch,
            frame.depth.texture.is_some(),
            frame.camera.available,
            frame.camera.world_transform.available,
            frame.depth.world_projection.reversed_depth,
            world_color,
            taa_enabled,
            taa_alpha_ready,
            fog.fog_available,
            fog.fog_color[0],
            fog.fog_color[1],
            fog.fog_color[2],
            fog.fog_start,
            fog.fog_end,
            fog.fog_power,
            frame.sky.is_some(),
            frame.sun.available,
            frame
                .material_state
                .exterior_known
                .then_some(frame.material_state.is_exterior),
            frame.underwater.hook_available,
            underwater_epoch_matches.then_some(frame.underwater.underwater),
            frame.underwater.frame_epoch,
            frame.distance_bound,
        );
    }

    fn log_integration_gate(&mut self, gate: FogIntegrationGate, settings: AtmosphereSettings) {
        if self.last_integration_gate == Some(gate) || self.integration_gate_logs >= 32 {
            return;
        }
        self.last_integration_gate = Some(gate);
        self.integration_gate_logs += 1;
        log::info!(
            "[ATMOSPHERE] Fog integration gate: {}, quality={:?}, scale={}, samples={}, density={:.8}, height_density={:.8}, noise={:.4}, inactive_noise_speed={:.4}, inactive_temporal_stability={:.4}",
            gate.label(),
            settings.quality,
            settings.target_scale(),
            settings.sample_count(),
            settings.density,
            settings.height_density,
            settings.noise_amount,
            settings.noise_speed,
            settings.temporal_stability,
        );
    }
}

fn log_composition_gate(
    last_gate: &mut Option<FogCompositionGate>,
    gate_logs: &mut u32,
    gate: FogCompositionGate,
    integration_draws: u64,
    composition_draws: u64,
    debug_draws: u64,
) {
    if *last_gate == Some(gate) || *gate_logs >= 32 {
        return;
    }
    *last_gate = Some(gate);
    *gate_logs += 1;
    log::info!(
        "[ATMOSPHERE] Fog composition gate: {}, transfer={}, integration_draws={}, compose_draws={}, debug_draws={}",
        gate.label(),
        SOURCE_TRANSFER.label(),
        integration_draws,
        composition_draws,
        debug_draws,
    );
}

fn draw_depth_reduce(
    device: &Device9Ref<'_>,
    shader: &PixelShader9,
    targets: &AtmosphereTargets,
    desc: &D3DSURFACE_DESC,
    frame: AtmosphereFrame,
    depth: DepthTexture,
) -> Direct3DResult<()> {
    bind_target(
        device,
        &targets.depth.surface,
        targets.width,
        targets.height,
    )?;
    unsafe {
        device.set_raw_base_texture(0, depth.as_ptr())?;
    }
    set_sampler_filter(device, 0, D3DTEXF_POINT.0 as u32)?;
    device.set_pixel_shader_constant_f(
        0,
        &[
            [
                desc.Width as f32,
                desc.Height as f32,
                1.0 / desc.Width.max(1) as f32,
                1.0 / desc.Height.max(1) as f32,
            ],
            [
                targets.width as f32,
                targets.height as f32,
                targets.inv_width,
                targets.inv_height,
            ],
            [
                frame.camera.near_z,
                frame.camera.far_z,
                frame.depth.world_projection.reversed_depth_f32(),
                frame.distance_bound,
            ],
            [
                frame.camera.frustum_left,
                frame.camera.frustum_right,
                frame.camera.frustum_bottom,
                frame.camera.frustum_top,
            ],
        ],
    )?;
    device.set_pixel_shader(shader)?;
    draw_quad(device, targets.width, targets.height)
}

fn draw_shaft_mask(
    device: &Device9Ref<'_>,
    shader: &PixelShader9,
    atmosphere: &AtmosphereTargets,
    shafts: &ShaftTargets,
    frame: AtmosphereFrame,
) -> Direct3DResult<()> {
    bind_target(device, &shafts.mask.surface, shafts.width, shafts.height)?;
    device.set_texture(0, &atmosphere.depth.texture)?;
    set_sampler_filter(device, 0, D3DTEXF_POINT.0 as u32)?;
    device.set_pixel_shader_constant_f(
        0,
        &[
            [
                shafts.width as f32,
                shafts.height as f32,
                shafts.inv_width,
                shafts.inv_height,
            ],
            [
                atmosphere.width as f32,
                atmosphere.height as f32,
                atmosphere.inv_width,
                atmosphere.inv_height,
            ],
            [frame.distance_bound, 0.0, 0.0, 0.0],
        ],
    )?;
    device.set_pixel_shader(shader)?;
    draw_quad(device, shafts.width, shafts.height)
}

fn draw_shaft_radial(
    device: &Device9Ref<'_>,
    shader: &PixelShader9,
    shafts: &ShaftTargets,
    light: DirectionalLight,
    settings: AtmosphereSettings,
) -> Direct3DResult<()> {
    bind_target(device, &shafts.radial.surface, shafts.width, shafts.height)?;
    device.set_texture(0, &shafts.mask.texture)?;
    set_sampler_filter(device, 0, D3DTEXF_LINEAR.0 as u32)?;
    device.set_pixel_shader_constant_f(
        0,
        &[
            [
                shafts.width as f32,
                shafts.height as f32,
                shafts.inv_width,
                shafts.inv_height,
            ],
            [
                light.projection.uv[0],
                light.projection.uv[1],
                light.projection.edge_fade,
                settings.shaft_strength,
            ],
        ],
    )?;
    device.set_pixel_shader(shader)?;
    draw_quad(device, shafts.width, shafts.height)
}

#[allow(clippy::too_many_arguments)]
fn draw_integration(
    device: &Device9Ref<'_>,
    shader: &PixelShader9,
    targets: &AtmosphereTargets,
    density_noise: &Texture9,
    shaft_visibility: &Texture9,
    frame: AtmosphereFrame,
    settings: AtmosphereSettings,
    contributions: AtmosphereContributions,
    shaft_ready: bool,
    far_layer: bool,
) -> Direct3DResult<()> {
    bind_target(
        device,
        if far_layer {
            &targets.far_atmosphere.surface
        } else {
            &targets.near_atmosphere.surface
        },
        targets.width,
        targets.height,
    )?;
    device.set_texture(0, &targets.depth.texture)?;
    device.set_texture(1, density_noise)?;
    device.set_texture(2, shaft_visibility)?;
    set_sampler_filter(device, 0, D3DTEXF_POINT.0 as u32)?;
    set_sampler_filter(device, 1, D3DTEXF_LINEAR.0 as u32)?;
    set_sampler_filter(device, 2, D3DTEXF_LINEAR.0 as u32)?;
    device.set_sampler_state(1, D3DSAMP_ADDRESSU, D3DTADDRESS_WRAP.0 as u32)?;
    device.set_sampler_state(1, D3DSAMP_ADDRESSV, D3DTADDRESS_WRAP.0 as u32)?;
    let view_to_world = view_to_world_rows(frame.camera);
    let light = contributions.light;
    let world_direction = light.map_or([0.0; 3], |light| light.world_direction);
    let sun_color = light.map_or([0.0; 3], |light| light.linear_color);
    let sun_disk_delta = light.map_or([0.0; 3], |light| light.linear_disk_delta);
    let daylight = light.map_or(0.0, |light| light.daylight);
    let fog_density = if settings.fog_enabled {
        settings.height_density
    } else {
        0.0
    };
    let noise_amount = if settings.fog_enabled {
        settings.noise_amount
    } else {
        0.0
    };
    device.set_pixel_shader_constant_f(
        0,
        &[
            [
                targets.width as f32,
                targets.height as f32,
                targets.inv_width,
                targets.inv_height,
            ],
            [
                frame.camera.near_z,
                frame.camera.far_z,
                frame.depth.world_projection.reversed_depth_f32(),
                frame.distance_bound,
            ],
            [
                frame.camera.frustum_left,
                frame.camera.frustum_right,
                frame.camera.frustum_bottom,
                frame.camera.frustum_top,
            ],
            view_to_world[0],
            view_to_world[1],
            view_to_world[2],
            [
                base_medium_density(settings, contributions),
                if contributions.fog { fog_density } else { 0.0 },
                settings.height_falloff,
                settings.base_height,
            ],
            [
                settings.max_distance,
                settings.effective_scattering_albedo(contributions.fog),
                if contributions.fog { noise_amount } else { 0.0 },
                settings.noise_scale,
            ],
            [
                contributions.medium_color[0],
                contributions.medium_color[1],
                contributions.medium_color[2],
                if contributions.fog { 1.0 } else { 0.0 },
            ],
            [1.0, 1.0, 0.0, if far_layer { 1.0 } else { 0.0 }],
            [
                settings.lighting_intensity,
                settings.anisotropy,
                settings.sun_disk_boost,
                if contributions.lighting_ready() {
                    1.0
                } else {
                    0.0
                },
            ],
            [
                world_direction[0],
                world_direction[1],
                world_direction[2],
                if shaft_ready { 1.0 } else { 0.0 },
            ],
            [sun_color[0], sun_color[1], sun_color[2], daylight],
            [sun_disk_delta[0], sun_disk_delta[1], sun_disk_delta[2], 0.0],
            [settings.lighting_medium_density, 0.0, 0.0, 0.0],
        ],
    )?;
    device.set_pixel_shader(shader)?;
    draw_quad(device, targets.width, targets.height)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScissorRect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

#[derive(Clone, Copy)]
struct UsableLocalLight<'a> {
    light: &'a crate::fnv_local_lights::LocalVolumetricLight,
    shadow: Option<crate::fnv_local_lights::LocalShadowBinding>,
}

fn local_light_scissor(
    camera: crate::backend::CameraFrame,
    width: u32,
    height: u32,
    world_position: [f32; 3],
    radius: f32,
    max_distance: f32,
) -> Option<ScissorRect> {
    if !camera.available
        || !camera.world_transform.available
        || width == 0
        || height == 0
        || !world_position.into_iter().all(f32::is_finite)
        || !radius.is_finite()
        || radius <= 0.0
        || !max_distance.is_finite()
        || max_distance <= 0.0
    {
        return None;
    }
    let transform = camera.world_transform;
    if !transform.scale.is_finite() || transform.scale.abs() <= 0.000001 {
        return None;
    }
    let delta = [
        world_position[0] - transform.translation[0],
        world_position[1] - transform.translation[1],
        world_position[2] - transform.translation[2],
    ];
    let center_distance = dot3(delta, delta).sqrt();
    if !center_distance.is_finite() || center_distance - radius >= max_distance {
        return None;
    }
    let inverse_scale = transform.scale.recip();
    let forward = [
        transform.rotation[0][0],
        transform.rotation[1][0],
        transform.rotation[2][0],
    ];
    let up = [
        transform.rotation[0][1],
        transform.rotation[1][1],
        transform.rotation[2][1],
    ];
    let right = [
        transform.rotation[0][2],
        transform.rotation[1][2],
        transform.rotation[2][2],
    ];
    let center = [
        dot3(delta, right) * inverse_scale,
        dot3(delta, up) * inverse_scale,
        dot3(delta, forward) * inverse_scale,
    ];
    let view_radius = radius * inverse_scale.abs();
    if !center.into_iter().all(f32::is_finite)
        || !view_radius.is_finite()
        || center[2] + view_radius <= 0.0
    {
        return None;
    }
    if center[2] - view_radius <= camera.near_z.max(0.0) {
        return Some(ScissorRect {
            left: 0,
            top: 0,
            right: width as i32,
            bottom: height as i32,
        });
    }

    let frustum_width = camera.frustum_right - camera.frustum_left;
    let frustum_height = camera.frustum_top - camera.frustum_bottom;
    if !frustum_width.is_finite()
        || !frustum_height.is_finite()
        || frustum_width <= 0.000001
        || frustum_height <= 0.000001
    {
        return None;
    }
    let mut min_uv = [f32::INFINITY; 2];
    let mut max_uv = [f32::NEG_INFINITY; 2];
    for x_sign in [-1.0f32, 1.0] {
        for y_sign in [-1.0f32, 1.0] {
            for z_sign in [-1.0f32, 1.0] {
                let z = center[2] + z_sign * view_radius;
                let projected_x = (center[0] + x_sign * view_radius) / z;
                let projected_y = (center[1] + y_sign * view_radius) / z;
                let uv = [
                    (projected_x - camera.frustum_left) / frustum_width,
                    (camera.frustum_top - projected_y) / frustum_height,
                ];
                if !uv.into_iter().all(f32::is_finite) {
                    return None;
                }
                min_uv[0] = min_uv[0].min(uv[0]);
                min_uv[1] = min_uv[1].min(uv[1]);
                max_uv[0] = max_uv[0].max(uv[0]);
                max_uv[1] = max_uv[1].max(uv[1]);
            }
        }
    }
    if max_uv[0] < 0.0 || max_uv[1] < 0.0 || min_uv[0] > 1.0 || min_uv[1] > 1.0 {
        return None;
    }
    let left = (min_uv[0].clamp(0.0, 1.0) * width as f32).floor() as i32 - 1;
    let top = (min_uv[1].clamp(0.0, 1.0) * height as f32).floor() as i32 - 1;
    let right = (max_uv[0].clamp(0.0, 1.0) * width as f32).ceil() as i32 + 1;
    let bottom = (max_uv[1].clamp(0.0, 1.0) * height as f32).ceil() as i32 + 1;
    let rect = ScissorRect {
        left: left.clamp(0, width as i32),
        top: top.clamp(0, height as i32),
        right: right.clamp(0, width as i32),
        bottom: bottom.clamp(0, height as i32),
    };
    (rect.left < rect.right && rect.top < rect.bottom).then_some(rect)
}

#[allow(clippy::too_many_arguments)]
fn draw_local_lights(
    device: &Device9Ref<'_>,
    pipeline: &LocalLightPipeline,
    targets: &AtmosphereTargets,
    density_noise: &Texture9,
    frame: AtmosphereFrame,
    settings: AtmosphereSettings,
    lights: &[Option<UsableLocalLight<'_>>; 4],
) -> Direct3DResult<LocalLightDrawStats> {
    let mut shadowless = [None; 4];
    let mut shadowless_count = 0usize;
    let mut shadowed = [None; 4];
    let mut shadowed_count = 0usize;
    for usable in lights.iter().flatten().copied() {
        if usable.shadow.is_some() {
            shadowed[shadowed_count] = Some(usable);
            shadowed_count += 1;
        } else {
            shadowless[shadowless_count] = Some(usable);
            shadowless_count += 1;
        }
    }

    let mut stats = LocalLightDrawStats::default();
    if shadowless_count != 0 {
        stats.add(draw_local_light_batch(
            device,
            pipeline,
            targets,
            density_noise,
            frame,
            settings,
            &shadowless,
            shadowless_count,
            false,
        )?);
    }
    for usable in shadowed.into_iter().take(shadowed_count).flatten() {
        stats.add(draw_local_light_batch(
            device,
            pipeline,
            targets,
            density_noise,
            frame,
            settings,
            &[Some(usable), None, None, None],
            1,
            true,
        )?);
    }
    Ok(stats)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct LocalLightDrawStats {
    draws: u32,
    lights: u32,
}

impl LocalLightDrawStats {
    fn add(&mut self, other: Self) {
        self.draws = self.draws.saturating_add(other.draws);
        self.lights = self.lights.saturating_add(other.lights);
    }
}

fn local_light_draw_count(shadowless_count: usize, shadowed_count: usize) -> u32 {
    2 * (u32::from(shadowless_count != 0) + shadowed_count.min(4) as u32)
}

fn union_scissor(current: Option<ScissorRect>, next: ScissorRect) -> ScissorRect {
    current.map_or(next, |current| ScissorRect {
        left: current.left.min(next.left),
        top: current.top.min(next.top),
        right: current.right.max(next.right),
        bottom: current.bottom.max(next.bottom),
    })
}

fn write_batched_light_constants(
    constants: &mut [[f32; 4]; 21],
    index: usize,
    values: crate::fnv_local_lights::LocalLightValues,
    intensity: f32,
) {
    debug_assert!(index < 4);
    constants[8 + index] = [
        values.position[0],
        values.position[1],
        values.position[2],
        values.radius,
    ];
    constants[12 + index] = [values.color[0], values.color[1], values.color[2], intensity];
}

#[allow(clippy::too_many_arguments)]
fn draw_local_light_batch(
    device: &Device9Ref<'_>,
    pipeline: &LocalLightPipeline,
    targets: &AtmosphereTargets,
    density_noise: &Texture9,
    frame: AtmosphereFrame,
    settings: AtmosphereSettings,
    lights: &[Option<UsableLocalLight<'_>>; 4],
    batch_size: usize,
    shadowed: bool,
) -> Direct3DResult<LocalLightDrawStats> {
    debug_assert!((1..=4).contains(&batch_size));
    debug_assert!(!shadowed || batch_size == 1);
    let contributions = resolve_contributions(frame, settings);
    let fog_active = contributions.fog;
    let view_to_world = view_to_world_rows(frame.camera);
    let debug_mode = match settings.lighting_debug_view() {
        6 => 1.0,
        7 => 2.0,
        8 => 3.0,
        _ => 0.0,
    };
    let height_density = if fog_active {
        settings.height_density
    } else {
        0.0
    };
    let noise_amount = if fog_active {
        settings.noise_amount
    } else {
        0.0
    };
    let mut constants = [[0.0f32; 4]; 21];
    constants[0] = [
        targets.width as f32,
        targets.height as f32,
        targets.inv_width,
        targets.inv_height,
    ];
    constants[1] = [
        frame.camera.near_z,
        frame.camera.far_z,
        frame.depth.world_projection.reversed_depth_f32(),
        frame.distance_bound,
    ];
    constants[2] = [
        frame.camera.frustum_left,
        frame.camera.frustum_right,
        frame.camera.frustum_bottom,
        frame.camera.frustum_top,
    ];
    constants[3] = view_to_world[0];
    constants[4] = view_to_world[1];
    constants[5] = view_to_world[2];
    constants[6] = [
        settings.effective_uniform_density(fog_active),
        height_density,
        settings.height_falloff,
        settings.base_height,
    ];
    constants[7] = [
        settings.max_distance,
        settings.effective_scattering_albedo(fog_active),
        noise_amount,
        settings.noise_scale,
    ];

    let mut scissor = None;
    for (index, usable) in lights.iter().take(batch_size).flatten().enumerate() {
        let light = usable.light;
        write_batched_light_constants(
            &mut constants,
            index,
            light.values,
            settings.local_lights_intensity,
        );
        if let Some(light_scissor) = local_light_scissor(
            frame.camera,
            targets.width,
            targets.height,
            light.values.position,
            light.values.radius,
            settings.max_distance,
        ) {
            scissor = Some(union_scissor(scissor, light_scissor));
        }
    }
    let Some(scissor) = scissor else {
        return Ok(LocalLightDrawStats::default());
    };

    let shadow = lights[0].and_then(|usable| usable.shadow);
    if shadowed {
        let Some(shadow) = shadow else {
            return Ok(LocalLightDrawStats::default());
        };
        constants[16][0] = shadow.values.format.bias();
        constants[17..21].copy_from_slice(&shadow.values.shadow_matrix);
    }
    constants[16][2] = settings.anisotropy;
    constants[16][3] = debug_mode;

    let shader = pipeline.shader(settings.local_shader_index(), shadowed, batch_size);
    draw_local_light_layer(
        device,
        &targets.near_atmosphere.surface,
        targets,
        density_noise,
        shadow,
        scissor,
        shader,
        &constants,
    )?;

    constants[16][1] = 1.0;
    draw_local_light_layer(
        device,
        &targets.far_atmosphere.surface,
        targets,
        density_noise,
        shadow,
        scissor,
        shader,
        &constants,
    )?;

    Ok(LocalLightDrawStats {
        draws: 2,
        lights: batch_size as u32,
    })
}

#[allow(clippy::too_many_arguments)]
fn draw_local_light_layer(
    device: &Device9Ref<'_>,
    target: &Surface9,
    targets: &AtmosphereTargets,
    density_noise: &Texture9,
    shadow: Option<crate::fnv_local_lights::LocalShadowBinding>,
    scissor: ScissorRect,
    shader: &PixelShader9,
    constants: &[[f32; 4]; 21],
) -> Direct3DResult<()> {
    // bind_target clears s0..s4 to prevent render-target feedback. Every input
    // must be rebound after it, for both the near and far layer.
    bind_target(device, target, targets.width, targets.height)?;
    device.set_texture(0, &targets.depth.texture)?;
    device.set_texture(1, density_noise)?;
    if let Some(shadow) = shadow {
        unsafe { device.set_raw_base_texture(2, shadow.texture)? };
        set_sampler_filter(device, 2, D3DTEXF_POINT.0 as u32)?;
    } else {
        device.clear_texture(2)?;
    }
    set_sampler_filter(device, 0, D3DTEXF_POINT.0 as u32)?;
    set_sampler_filter(device, 1, D3DTEXF_LINEAR.0 as u32)?;
    device.set_sampler_state(1, D3DSAMP_ADDRESSU, D3DTADDRESS_WRAP.0 as u32)?;
    device.set_sampler_state(1, D3DSAMP_ADDRESSV, D3DTADDRESS_WRAP.0 as u32)?;
    device.set_render_state(D3DRS_ALPHABLENDENABLE, 1)?;
    device.set_render_state(D3DRS_SRCBLEND, D3DBLEND_ONE.0 as u32)?;
    device.set_render_state(D3DRS_DESTBLEND, D3DBLEND_ONE.0 as u32)?;
    device.set_render_state(D3DRS_BLENDOP, D3DBLENDOP_ADD.0 as u32)?;
    device.set_render_state(D3DRS_COLORWRITEENABLE, 0x07)?;
    device.set_render_state(D3DRS_SCISSORTESTENABLE, 1)?;
    device.set_scissor_rect(scissor.left, scissor.top, scissor.right, scissor.bottom)?;
    device.set_pixel_shader_constant_f(0, constants)?;
    device.set_pixel_shader(shader)?;
    draw_quad(device, targets.width, targets.height)
}

#[allow(clippy::too_many_arguments)]
fn draw_composition(
    device: &Device9Ref<'_>,
    shader: &PixelShader9,
    world_target: &Surface9,
    desc: &D3DSURFACE_DESC,
    targets: &AtmosphereTargets,
    world_color: &Texture9,
    depth: DepthTexture,
    frame: AtmosphereFrame,
    debug_acceptance: bool,
) -> Direct3DResult<()> {
    bind_target(device, world_target, desc.Width, desc.Height)?;
    device.set_texture(0, world_color)?;
    unsafe {
        device.set_raw_base_texture(1, depth.as_ptr())?;
    }
    device.set_texture(2, &targets.depth.texture)?;
    device.set_texture(3, &targets.near_atmosphere.texture)?;
    device.set_texture(4, &targets.far_atmosphere.texture)?;
    for sampler in 0..=4 {
        set_sampler_filter(device, sampler, D3DTEXF_POINT.0 as u32)?;
    }
    device.set_pixel_shader_constant_f(
        0,
        &[
            [
                desc.Width as f32,
                desc.Height as f32,
                1.0 / desc.Width.max(1) as f32,
                1.0 / desc.Height.max(1) as f32,
            ],
            [
                targets.width as f32,
                targets.height as f32,
                targets.inv_width,
                targets.inv_height,
            ],
            [
                frame.camera.near_z,
                frame.camera.far_z,
                frame.depth.world_projection.reversed_depth_f32(),
                frame.distance_bound,
            ],
            [
                frame.camera.frustum_left,
                frame.camera.frustum_right,
                frame.camera.frustum_bottom,
                frame.camera.frustum_top,
            ],
            [
                targets.scale as f32,
                64.0,
                0.02,
                if debug_acceptance { 1.0 } else { 0.0 },
            ],
        ],
    )?;
    device.set_pixel_shader(shader)?;
    draw_quad(device, desc.Width, desc.Height)
}

#[allow(clippy::too_many_arguments)]
fn draw_debug(
    device: &Device9Ref<'_>,
    shader: &PixelShader9,
    world_target: &Surface9,
    desc: &D3DSURFACE_DESC,
    targets: &AtmosphereTargets,
    world_color: &Texture9,
    frame: AtmosphereFrame,
    debug_view: i32,
    integration_ready: bool,
    settings: AtmosphereSettings,
    contributions: AtmosphereContributions,
    shaft_ready: bool,
    shaft_targets: Option<&ShaftTargets>,
    neutral_visibility: &Texture9,
) -> Direct3DResult<()> {
    bind_target(device, world_target, desc.Width, desc.Height)?;
    device.set_texture(0, world_color)?;
    device.set_texture(1, &targets.depth.texture)?;
    device.set_texture(2, &targets.far_atmosphere.texture)?;
    device.set_texture(
        3,
        shaft_targets.map_or(neutral_visibility, |targets| &targets.mask.texture),
    )?;
    device.set_texture(
        4,
        shaft_targets.map_or(neutral_visibility, |targets| &targets.radial.texture),
    )?;
    set_sampler_filter(device, 0, D3DTEXF_LINEAR.0 as u32)?;
    set_sampler_filter(device, 1, D3DTEXF_POINT.0 as u32)?;
    set_sampler_filter(device, 2, D3DTEXF_LINEAR.0 as u32)?;
    set_sampler_filter(device, 3, D3DTEXF_LINEAR.0 as u32)?;
    set_sampler_filter(device, 4, D3DTEXF_LINEAR.0 as u32)?;
    let view_to_world = view_to_world_rows(frame.camera);
    let light = contributions.light;
    let direction = light.map_or([0.0; 3], |light| light.world_direction);
    let color = light.map_or([0.0; 3], |light| light.linear_color);
    let disk_delta = light.map_or([0.0; 3], |light| light.linear_disk_delta);
    let daylight = light.map_or(0.0, |light| light.daylight);
    device.set_pixel_shader_constant_f(
        0,
        &[
            [
                desc.Width as f32,
                desc.Height as f32,
                1.0 / desc.Width.max(1) as f32,
                1.0 / desc.Height.max(1) as f32,
            ],
            [
                targets.width as f32,
                targets.height as f32,
                targets.inv_width,
                targets.inv_height,
            ],
            [
                frame.distance_bound,
                debug_view as f32,
                if frame.camera.world_transform.available {
                    1.0
                } else {
                    0.0
                },
                if integration_ready { 1.0 } else { 0.0 },
            ],
            [
                frame.camera.frustum_left,
                frame.camera.frustum_right,
                frame.camera.frustum_bottom,
                frame.camera.frustum_top,
            ],
            view_to_world[0],
            view_to_world[1],
            view_to_world[2],
            [
                settings.anisotropy,
                settings.lighting_intensity,
                settings.sun_disk_boost,
                if contributions.lighting_ready() {
                    1.0
                } else {
                    0.0
                },
            ],
            [
                direction[0],
                direction[1],
                direction[2],
                if shaft_ready { 1.0 } else { 0.0 },
            ],
            [color[0], color[1], color[2], daylight],
            [disk_delta[0], disk_delta[1], disk_delta[2], 0.0],
            [settings.lighting_medium_density, 0.0, 0.0, 0.0],
        ],
    )?;
    device.set_pixel_shader(shader)?;
    draw_quad(device, desc.Width, desc.Height)
}

fn view_to_world_rows(camera: crate::backend::CameraFrame) -> [[f32; 4]; 3] {
    let transform = camera.world_transform;
    if !transform.available {
        return [[0.0; 4]; 3];
    }
    [
        [
            transform.rotation[0][2] * transform.scale,
            transform.rotation[0][1] * transform.scale,
            transform.rotation[0][0] * transform.scale,
            transform.translation[0],
        ],
        [
            transform.rotation[1][2] * transform.scale,
            transform.rotation[1][1] * transform.scale,
            transform.rotation[1][0] * transform.scale,
            transform.translation[1],
        ],
        [
            transform.rotation[2][2] * transform.scale,
            transform.rotation[2][1] * transform.scale,
            transform.rotation[2][0] * transform.scale,
            transform.translation[2],
        ],
    ]
}

fn fog_integration_gate(
    frame: AtmosphereFrame,
    settings: AtmosphereSettings,
    local_ready: bool,
) -> FogIntegrationGate {
    if !settings.fog_enabled && !settings.lighting_enabled && !settings.local_lights_enabled {
        return FogIntegrationGate::Disabled;
    }
    if !settings.requires_integration() {
        return FogIntegrationGate::EmptyMedium;
    }
    if frame.depth_contract_failure().is_some() {
        return FogIntegrationGate::MissingDepthContract;
    }
    if !frame.camera.world_transform.available {
        return FogIntegrationGate::MissingWorldTransform;
    }
    if !frame.material_state.exterior_known {
        return FogIntegrationGate::ExteriorUnknown;
    }
    if !frame.material_state.is_exterior && !local_ready {
        return FogIntegrationGate::Interior;
    }
    if !frame.underwater_contract_ready() {
        return FogIntegrationGate::UnderwaterUnknown;
    }
    if frame.underwater.underwater {
        return FogIntegrationGate::Underwater;
    }
    if !resolve_contributions(frame, settings).any() && !local_ready {
        return FogIntegrationGate::NoReadyContribution;
    }
    FogIntegrationGate::Ready
}

fn fog_composition_gate(
    integration_gate: FogIntegrationGate,
    integration_ready: bool,
    world_color_available: bool,
    desc: &D3DSURFACE_DESC,
    settings: AtmosphereSettings,
    taa_enabled: bool,
    taa_alpha_ready: bool,
) -> FogCompositionGate {
    if settings.debug_view != 0 && settings.lighting_debug_view() < 6 {
        return FogCompositionGate::DebugView;
    }
    if integration_gate != FogIntegrationGate::Ready || !integration_ready {
        return FogCompositionGate::IntegrationUnavailable;
    }
    if !world_color_available {
        return FogCompositionGate::MissingWorldColor;
    }
    if desc.Format != D3DFMT_A16B16G16R16F || desc.Usage & USAGE_RENDER_TARGET == 0 {
        return FogCompositionGate::UnsupportedWorldTarget;
    }
    if taa_enabled && !taa_alpha_ready {
        return FogCompositionGate::TaaAlphaUnavailable;
    }
    FogCompositionGate::Ready
}

fn resolve_medium_color(frame: AtmosphereFrame) -> Option<MediumColor> {
    if !frame.material_state.exterior_known || !frame.material_state.is_exterior {
        return None;
    }
    if frame.environment.fog_available
        && let Some(linear_rgb) = linearize_native_color(frame.environment.fog_color)
    {
        return Some(MediumColor { linear_rgb });
    }
    let sky = frame.sky?;
    if !sky.is_exterior {
        return None;
    }
    linearize_native_color(sky.horizon).map(|linear_rgb| MediumColor { linear_rgb })
}

fn resolve_contributions(
    frame: AtmosphereFrame,
    settings: AtmosphereSettings,
) -> AtmosphereContributions {
    let medium_color = settings
        .fog_enabled
        .then(|| resolve_medium_color(frame))
        .flatten();
    AtmosphereContributions {
        medium_color: medium_color.map_or([0.0; 3], |color| color.linear_rgb),
        fog: medium_color.is_some(),
        light: settings
            .lighting_enabled
            .then(|| resolve_directional_light(frame))
            .flatten(),
    }
}

fn base_medium_density(
    settings: AtmosphereSettings,
    contributions: AtmosphereContributions,
) -> f32 {
    if contributions.fog || contributions.lighting_ready() {
        settings.effective_uniform_density(contributions.fog)
    } else {
        0.0
    }
}

fn resolve_directional_light(frame: AtmosphereFrame) -> Option<DirectionalLight> {
    if !frame.material_state.exterior_known || !frame.material_state.is_exterior {
        return None;
    }
    let sky = frame.sky?;
    if !sky.is_exterior || !sky.daylight.is_finite() || sky.daylight <= 0.001 {
        return None;
    }
    let length = dot3(sky.sun_direction, sky.sun_direction).sqrt();
    if !length.is_finite() || !(0.99..=1.01).contains(&length) {
        return None;
    }
    let linear_color = linearize_native_color(sky.sun_light)?;
    let linear_disk = linearize_native_color(sky.sun_disk)?;
    let linear_disk_delta = [
        (linear_disk[0] - linear_color[0]).max(0.0),
        (linear_disk[1] - linear_color[1]).max(0.0),
        (linear_disk[2] - linear_color[2]).max(0.0),
    ];
    let projection = project_sun_from_captured_camera(frame.camera, sky.sun_direction);
    if projection.facing <= 0.001 || !projection.on_screen || projection.edge_fade <= 0.0 {
        return None;
    }
    Some(DirectionalLight {
        world_direction: sky.sun_direction,
        linear_color,
        linear_disk_delta,
        daylight: sky.daylight.clamp(0.0, 1.0) * projection.edge_fade,
        projection,
    })
}

fn linearize_native_color(color: [f32; 3]) -> Option<[f32; 3]> {
    if !color.into_iter().all(f32::is_finite) {
        return None;
    }
    let linear = color.map(|component| decode_extended_srgb(component.max(0.0)));
    linear.into_iter().all(f32::is_finite).then_some(linear)
}

fn decode_extended_srgb(component: f32) -> f32 {
    if component <= 0.04045 {
        component / 12.92
    } else {
        ((component.max(0.0) + 0.055) / 1.055).powf(2.4)
    }
}

#[cfg(test)]
fn encode_extended_srgb(component: f32) -> f32 {
    if component <= 0.0031308 {
        component * 12.92
    } else {
        component.abs().powf(1.0 / 2.4) * 1.055 - 0.055
    }
}

#[cfg(test)]
fn layered_tap_weight(full_distance: f32, nearest: f32, farthest: f32, scale: u32) -> f32 {
    let base_tolerance = (64.0 * scale.max(1) as f32).max(full_distance * 0.02);
    let farthest = farthest.max(nearest);
    let matched_distance = full_distance.clamp(nearest, farthest);
    let depth_weight =
        (1.0 - (full_distance - matched_distance).abs() / base_tolerance.max(1.0)).clamp(0.0, 1.0);
    depth_weight * depth_weight
}

#[cfg(test)]
fn atmosphere_layer_blend(full_distance: f32, nearest: f32, farthest: f32) -> f32 {
    let span = (farthest - nearest).max(0.0);
    if span <= 0.0001 {
        0.0
    } else {
        ((full_distance.clamp(nearest, farthest) - nearest) / span).clamp(0.0, 1.0)
    }
}

fn option_component(
    constants: Option<&[[f32; 4]]>,
    register: usize,
    component: usize,
    fallback: f32,
) -> f32 {
    constants
        .and_then(|constants| constants.get(register))
        .map_or(fallback, |value| value[component])
}

fn compile_shader(
    device: &Device9Ref<'_>,
    source_name: &str,
    source: &[u8],
) -> Direct3DResult<PixelShader9> {
    let bytecode = match shaders::compile_hlsl_source(source_name, source) {
        Ok(bytecode) => bytecode,
        Err(err) => {
            log::warn!("[ATMOSPHERE] Failed to compile {source_name}: {err:#}");
            return Err(direct3d_failure());
        }
    };
    device.create_pixel_shader(&bytecode)
}

fn depth_reduce_shader_source(scale: u32) -> Vec<u8> {
    let mut variant = format!("#define ATMOSPHERE_REDUCTION_SCALE {scale}\n").into_bytes();
    variant.extend_from_slice(DEPTH_REDUCE_SHADER);
    variant
}

fn integration_shader_source(sample_count: u32) -> Vec<u8> {
    let mut variant = format!("#define ATMOSPHERE_SAMPLE_COUNT {sample_count}\n").into_bytes();
    variant.extend_from_slice(INTEGRATE_SHADER);
    variant
}

fn shaft_radial_shader_source(sample_count: u32) -> Vec<u8> {
    let mut variant =
        format!("#define ATMOSPHERE_SHAFT_SAMPLE_COUNT {sample_count}\n").into_bytes();
    variant.extend_from_slice(SHAFT_RADIAL_SHADER);
    variant
}

fn local_light_shader_source(
    sample_count: u32,
    batch_size: usize,
    use_noise: bool,
    use_native_shadow: bool,
) -> Vec<u8> {
    debug_assert!((1..=4).contains(&batch_size));
    debug_assert!(!use_native_shadow || batch_size == 1);
    let mut variant = format!(
        "#define LOCAL_LIGHT_SAMPLE_COUNT {sample_count}\n#define LOCAL_LIGHT_BATCH_SIZE {batch_size}\n#define LOCAL_LIGHT_USE_NOISE {}\n#define LOCAL_LIGHT_USE_NATIVE_SHADOW {}\n",
        u8::from(use_noise),
        u8::from(use_native_shadow),
    )
    .into_bytes();
    variant.extend_from_slice(LOCAL_LIGHT_SHADER);
    variant
}

fn create_density_noise(device: &Device9Ref<'_>) -> Direct3DResult<Texture9> {
    let texture = device.create_texture(
        DENSITY_NOISE_SIZE,
        DENSITY_NOISE_SIZE,
        1,
        0,
        D3DFMT_A8R8G8B8,
        D3DPOOL_MANAGED,
    )?;
    let pixels = density_noise_pixels();
    texture.write_level0_argb(DENSITY_NOISE_SIZE, DENSITY_NOISE_SIZE, &pixels)?;
    log::info!(
        "[ATMOSPHERE] Density noise: {}x{} A8R8G8B8, seed=0x{:08X}",
        DENSITY_NOISE_SIZE,
        DENSITY_NOISE_SIZE,
        DENSITY_NOISE_SEED,
    );
    Ok(texture)
}

fn create_neutral_visibility(device: &Device9Ref<'_>) -> Direct3DResult<Texture9> {
    let texture = device.create_texture(1, 1, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)?;
    texture.write_level0_argb(1, 1, &[0xFFFF_FFFF])?;
    Ok(texture)
}

fn density_noise_pixels() -> Vec<u32> {
    let mut pixels = Vec::with_capacity((DENSITY_NOISE_SIZE * DENSITY_NOISE_SIZE) as usize);
    for y in 0..DENSITY_NOISE_SIZE {
        for x in 0..DENSITY_NOISE_SIZE {
            let coordinate = x | (y << 16);
            let red = hash_byte(coordinate ^ DENSITY_NOISE_SEED);
            let green = hash_byte(coordinate ^ DENSITY_NOISE_SEED.rotate_left(11));
            let blue = hash_byte(coordinate ^ DENSITY_NOISE_SEED.rotate_left(23));
            pixels.push(0xFF00_0000 | ((red as u32) << 16) | ((green as u32) << 8) | blue as u32);
        }
    }
    pixels
}

fn hash_byte(mut value: u32) -> u8 {
    value ^= value >> 16;
    value = value.wrapping_mul(0x7FEB_352D);
    value ^= value >> 15;
    value = value.wrapping_mul(0x846C_A68B);
    value ^= value >> 16;
    (value >> 24) as u8
}

fn bind_pipeline_state(device: &Device9Ref<'_>) -> Direct3DResult<()> {
    device.clear_vertex_shader()?;
    device.set_fvf(ScreenVertex::FVF)?;
    device.set_render_state(D3DRS_CULLMODE, D3DCULL_NONE.0 as u32)?;
    device.set_render_state(D3DRS_ALPHABLENDENABLE, 0)?;
    device.set_render_state(D3DRS_ALPHATESTENABLE, 0)?;
    device.set_render_state(D3DRS_ZENABLE, 0)?;
    device.set_render_state(D3DRS_ZWRITEENABLE, 0)?;
    device.set_render_state(D3DRS_STENCILENABLE, 0)?;
    device.set_render_state(D3DRS_SCISSORTESTENABLE, 0)?;
    device.set_render_state(D3DRS_MULTISAMPLEANTIALIAS, 1)?;
    device.set_render_state(D3DRS_MULTISAMPLEMASK, u32::MAX)?;
    match crate::backend::fnv_alpha_coverage_mode() {
        crate::backend::AlphaCoverageMode::None => {}
        crate::backend::AlphaCoverageMode::Nvidia => {
            device.set_render_state(D3DRS_ADAPTIVETESS_Y, 0)?;
        }
        crate::backend::AlphaCoverageMode::Amd => {
            device.set_render_state(D3DRS_POINTSIZE, AMD_ALPHA_TO_COVERAGE_OFF)?;
        }
    }
    device.set_render_state(D3DRS_SRGBWRITEENABLE, 0)?;
    device.set_render_state(D3DRS_COLORWRITEENABLE, COLOR_WRITE_ALL)?;
    for sampler in 0..=4 {
        device.set_sampler_state(sampler, D3DSAMP_ADDRESSU, D3DTADDRESS_CLAMP.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_ADDRESSV, D3DTADDRESS_CLAMP.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_MINFILTER, D3DTEXF_POINT.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_MAGFILTER, D3DTEXF_POINT.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_MIPFILTER, D3DTEXF_NONE.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_SRGBTEXTURE, 0)?;
    }
    device.set_texture_stage_state(0, D3DTSS_COLOROP, D3DTOP_SELECTARG1.0 as u32)?;
    device.set_texture_stage_state(0, D3DTSS_COLORARG1, D3DTA_TEXTURE)?;
    device.set_texture_stage_state(0, D3DTSS_ALPHAOP, D3DTOP_SELECTARG1.0 as u32)?;
    device.set_texture_stage_state(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE)
}

fn bind_target(
    device: &Device9Ref<'_>,
    surface: &Surface9,
    width: u32,
    height: u32,
) -> Direct3DResult<()> {
    device.clear_texture(0)?;
    device.clear_texture(1)?;
    device.clear_texture(2)?;
    device.clear_texture(3)?;
    device.clear_texture(4)?;
    device.set_depth_stencil_surface(None)?;
    for index in 1..=3 {
        device.clear_render_target(index)?;
    }
    device.set_render_target(0, surface)?;
    device.set_viewport(&D3DVIEWPORT9 {
        X: 0,
        Y: 0,
        Width: width,
        Height: height,
        MinZ: 0.0,
        MaxZ: 1.0,
    })
}

fn set_sampler_filter(device: &Device9Ref<'_>, sampler: u32, filter: u32) -> Direct3DResult<()> {
    device.set_sampler_state(sampler, D3DSAMP_MINFILTER, filter)?;
    device.set_sampler_state(sampler, D3DSAMP_MAGFILTER, filter)
}

fn draw_quad(device: &Device9Ref<'_>, width: u32, height: u32) -> Direct3DResult<()> {
    let width = width as f32;
    let height = height as f32;
    let quad = [
        ScreenVertex::new(-0.5, -0.5, 0.0, 0.0),
        ScreenVertex::new(width - 0.5, -0.5, 1.0, 0.0),
        ScreenVertex::new(-0.5, height - 0.5, 0.0, 1.0),
        ScreenVertex::new(width - 0.5, height - 0.5, 1.0, 1.0),
    ];
    unsafe { device.draw_primitive_up(D3DPT_TRIANGLESTRIP, 2, &quad) }
}

fn finite(value: f32, fallback: f32) -> f32 {
    if value.is_finite() { value } else { fallback }
}

fn finite_i32(value: f32) -> i32 {
    if value.is_finite() {
        value.round().clamp(i32::MIN as f32, i32::MAX as f32) as i32
    } else {
        0
    }
}

fn quantize(value: f32, scale: f32) -> i32 {
    finite_i32(finite(value, 0.0) * scale)
}

struct AtmosphereTargets {
    full_width: u32,
    full_height: u32,
    scale: u32,
    width: u32,
    height: u32,
    inv_width: f32,
    inv_height: f32,
    depth: EffectTarget,
    near_atmosphere: EffectTarget,
    far_atmosphere: EffectTarget,
}

impl AtmosphereTargets {
    fn create(
        device: &Device9Ref<'_>,
        full_width: u32,
        full_height: u32,
        scale: u32,
    ) -> Direct3DResult<Self> {
        let scale = scale.clamp(2, 4);
        let width = full_width.div_ceil(scale).max(1);
        let height = full_height.div_ceil(scale).max(1);
        Ok(Self {
            full_width,
            full_height,
            scale,
            width,
            height,
            inv_width: 1.0 / width as f32,
            inv_height: 1.0 / height as f32,
            depth: EffectTarget::create(device, width, height, D3DFMT_G16R16F)?,
            near_atmosphere: EffectTarget::create(device, width, height, D3DFMT_A16B16G16R16F)?,
            far_atmosphere: EffectTarget::create(device, width, height, D3DFMT_A16B16G16R16F)?,
        })
    }

    fn matches(&self, full_width: u32, full_height: u32, scale: u32) -> bool {
        self.full_width == full_width && self.full_height == full_height && self.scale == scale
    }
}

struct EffectTarget {
    texture: Texture9,
    surface: Surface9,
}

struct LocalLightPipeline {
    shadowless_shaders: [[PixelShader9; 4]; 3],
    shadowed_shaders: [PixelShader9; 3],
}

impl LocalLightPipeline {
    fn create(device: &Device9Ref<'_>) -> Direct3DResult<Self> {
        device
            .direct3d()?
            .check_default_render_target_blending_support(D3DFMT_A16B16G16R16F)?;
        Ok(Self {
            shadowless_shaders: [
                compile_local_light_batch(device, "performance", 4, false)?,
                compile_local_light_batch(device, "high", 6, true)?,
                compile_local_light_batch(device, "ultra", 10, true)?,
            ],
            shadowed_shaders: [
                compile_shader(
                    device,
                    "atmosphere_local_light.hlsl:performance:shadowed",
                    &local_light_shader_source(4, 1, false, true),
                )?,
                compile_shader(
                    device,
                    "atmosphere_local_light.hlsl:high:shadowed",
                    &local_light_shader_source(6, 1, true, true),
                )?,
                compile_shader(
                    device,
                    "atmosphere_local_light.hlsl:ultra:shadowed",
                    &local_light_shader_source(10, 1, true, true),
                )?,
            ],
        })
    }

    fn shader(&self, quality_index: usize, shadowed: bool, batch_size: usize) -> &PixelShader9 {
        if shadowed {
            debug_assert_eq!(batch_size, 1);
            &self.shadowed_shaders[quality_index]
        } else {
            &self.shadowless_shaders[quality_index][batch_size.saturating_sub(1).min(3)]
        }
    }
}

fn compile_local_light_batch(
    device: &Device9Ref<'_>,
    quality: &str,
    sample_count: u32,
    use_noise: bool,
) -> Direct3DResult<[PixelShader9; 4]> {
    Ok([
        compile_shader(
            device,
            &format!("atmosphere_local_light.hlsl:{quality}:shadowless:batch=1"),
            &local_light_shader_source(sample_count, 1, use_noise, false),
        )?,
        compile_shader(
            device,
            &format!("atmosphere_local_light.hlsl:{quality}:shadowless:batch=2"),
            &local_light_shader_source(sample_count, 2, use_noise, false),
        )?,
        compile_shader(
            device,
            &format!("atmosphere_local_light.hlsl:{quality}:shadowless:batch=3"),
            &local_light_shader_source(sample_count, 3, use_noise, false),
        )?,
        compile_shader(
            device,
            &format!("atmosphere_local_light.hlsl:{quality}:shadowless:batch=4"),
            &local_light_shader_source(sample_count, 4, use_noise, false),
        )?,
    ])
}

struct ShaftPipeline {
    mask_shader: PixelShader9,
    radial_shaders: [PixelShader9; 3],
}

impl ShaftPipeline {
    fn create(device: &Device9Ref<'_>) -> Direct3DResult<Self> {
        Ok(Self {
            mask_shader: compile_shader(device, "atmosphere_shaft_mask.hlsl", SHAFT_MASK_SHADER)?,
            radial_shaders: [
                compile_shader(
                    device,
                    "atmosphere_shaft_radial.hlsl:performance",
                    &shaft_radial_shader_source(24),
                )?,
                compile_shader(
                    device,
                    "atmosphere_shaft_radial.hlsl:high",
                    &shaft_radial_shader_source(40),
                )?,
                compile_shader(
                    device,
                    "atmosphere_shaft_radial.hlsl:ultra",
                    &shaft_radial_shader_source(56),
                )?,
            ],
        })
    }
}

struct ShaftTargets {
    width: u32,
    height: u32,
    inv_width: f32,
    inv_height: f32,
    mask: EffectTarget,
    radial: EffectTarget,
}

impl ShaftTargets {
    fn create(device: &Device9Ref<'_>, width: u32, height: u32) -> Direct3DResult<Self> {
        Ok(Self {
            width,
            height,
            inv_width: 1.0 / width as f32,
            inv_height: 1.0 / height as f32,
            mask: EffectTarget::create(device, width, height, D3DFMT_G16R16F)?,
            radial: EffectTarget::create(device, width, height, D3DFMT_G16R16F)?,
        })
    }

    fn matches(&self, width: u32, height: u32) -> bool {
        self.width == width && self.height == height
    }
}

impl EffectTarget {
    fn create(
        device: &Device9Ref<'_>,
        width: u32,
        height: u32,
        format: D3DFORMAT,
    ) -> Direct3DResult<Self> {
        let texture = device.create_render_target_texture(width, height, format)?;
        let surface = texture.surface_level(0)?;
        Ok(Self { texture, surface })
    }
}

#[cfg(test)]
mod feature_tests {
    use core::ffi::c_void;

    use super::{
        AtmosphereDrawOutcome, AtmosphereSettings, FogCompositionGate, FogIntegrationGate,
        atmosphere_layer_blend, base_medium_density, bounded_shaft_visibility,
        decode_extended_srgb, density_noise_pixels, directional_phase_response,
        directional_radiance, directional_scatter_amount, encode_extended_srgb,
        fog_composition_gate, fog_integration_gate, henyey_greenstein, integrated_uniform_scatter,
        layered_tap_weight, linearize_native_color, local_light_draw_count, local_light_scissor,
        option_component, project_native_shadow, project_sun_from_captured_camera,
        ray_sphere_interval, resolve_contributions, resolve_directional_light,
        resolve_medium_color, selected_debug_view, shaft_visibility_from_blocked_fraction,
        union_scissor, write_batched_light_constants,
    };
    use crate::{
        backend::{
            AtmosphereFrame, CameraFrame, CameraTransformFrame, DepthFrame, DepthProjectionFrame,
            DepthProvider, DepthTexture, EnvironmentFrame, MaterialStateFrame, NativeSkyFrame,
            SunFrame, UnderwaterFrame,
        },
        config::{AtmosphereQuality, EmbeddedEffectsConfig},
        shaders::{self, EmbeddedEffectKind},
    };

    fn settings() -> AtmosphereSettings {
        AtmosphereSettings {
            fog_enabled: true,
            lighting_enabled: false,
            density: 0.00001,
            height_density: 0.00002,
            height_falloff: 0.0001,
            base_height: 0.0,
            max_distance: 120_000.0,
            scattering_albedo: 0.9,
            noise_amount: 0.25,
            noise_scale: 0.0005,
            noise_speed: 0.02,
            temporal_stability: 0.9,
            debug_view: 0,
            quality: AtmosphereQuality::High,
            lighting_intensity: 1.0,
            lighting_medium_density: 0.00001,
            anisotropy: 0.65,
            shaft_strength: 1.0,
            sun_disk_boost: 1.0,
            shaft_quality: AtmosphereQuality::High,
            local_lights_enabled: false,
            local_lights_intensity: 1.0,
            local_lights_quality: AtmosphereQuality::High,
        }
    }

    fn valid_frame() -> AtmosphereFrame {
        let camera = CameraFrame {
            near_z: 5.0,
            far_z: 200_000.0,
            aspect_ratio: 16.0 / 9.0,
            frustum_left: -1.0,
            frustum_right: 1.0,
            frustum_bottom: -0.5625,
            frustum_top: 0.5625,
            world_transform: CameraTransformFrame {
                available: true,
                ..CameraTransformFrame::default()
            },
            available: true,
        };
        let projection = DepthProjectionFrame {
            camera,
            reversed_depth: Some(true),
            depth_function: Some(7),
            source_surface: 1,
            sampled_depth_bits: 24,
        };
        AtmosphereFrame {
            camera,
            depth: DepthFrame::from_textures(
                DepthProvider::FalloutNewVegas,
                DepthTexture::new(1usize as *mut c_void),
                None,
                projection,
                DepthProjectionFrame::default(),
                7,
            ),
            environment: EnvironmentFrame {
                fog_color: [0.4, 0.5, 0.6],
                fog_start: 1_000.0,
                fog_end: 120_000.0,
                fog_power: 1.0,
                fog_available: true,
            },
            underwater: UnderwaterFrame {
                frame_epoch: 7,
                hook_available: true,
                known: true,
                underwater: false,
            },
            sun: SunFrame::default(),
            sky: None,
            material_state: MaterialStateFrame {
                exterior_known: true,
                is_exterior: true,
            },
            frame_epoch: 7,
            distance_bound: 120_000.0,
        }
    }

    fn valid_sky(direction: [f32; 3]) -> NativeSkyFrame {
        NativeSkyFrame {
            sky_upper: [0.2, 0.3, 0.6],
            sky_lower: [0.4, 0.45, 0.55],
            horizon: [0.65, 0.6, 0.5],
            sun_light: [1.2, 1.0, 0.8],
            sun_disk: [2.0, 1.7, 1.1],
            sun_direction: direction,
            daylight: 0.85,
            game_hour: 12.0,
            is_exterior: true,
            reversed_depth: true,
        }
    }

    #[test]
    fn quality_selects_fixed_scale_and_sample_count() {
        let mut settings = settings();
        for (quality, scale, samples) in [
            (AtmosphereQuality::Performance, 4, 8),
            (AtmosphereQuality::High, 2, 12),
            (AtmosphereQuality::Ultra, 2, 20),
        ] {
            settings.quality = quality;
            assert_eq!(settings.target_scale(), scale);
            assert_eq!(settings.sample_count(), samples);
        }
    }

    #[test]
    fn shaft_quality_has_fixed_quarter_resolution_work_budgets() {
        let mut settings = settings();
        let width = 3440_u32.div_ceil(4);
        let height = 1440_u32.div_ceil(4);
        assert_eq!((width, height), (860, 360));

        for (quality, samples, expected_fetches) in [
            (AtmosphereQuality::Performance, 24, 7_430_400_u64),
            (AtmosphereQuality::High, 40, 12_384_000),
            (AtmosphereQuality::Ultra, 56, 17_337_600),
        ] {
            settings.shaft_quality = quality;
            assert_eq!(settings.shaft_sample_count(), samples);
            assert_eq!(u64::from(width * height * samples), expected_fetches);
        }

        let target_bytes = u64::from(width * height) * 4 * 2;
        assert_eq!(target_bytes, 2_476_800);
        assert!(target_bytes < 5 * 1024 * 1024);
    }

    #[test]
    fn calibrated_default_estimates_about_two_percent_extinction_at_observed_bound() {
        let mut config = EmbeddedEffectsConfig::default();
        config.volumetric_fog.enabled = true;
        let settings =
            AtmosphereSettings::from_config(config.volumetric_fog, config.volumetric_lighting);
        let mut frame = valid_frame();
        frame.distance_bound = 10_240.0;

        let transmittance = settings.estimated_horizontal_transmittance(frame);
        assert!((0.974..0.976).contains(&transmittance));
    }

    #[test]
    fn lighting_default_keeps_distant_extinction_bounded() {
        let mut config = EmbeddedEffectsConfig::default();
        config.volumetric_fog.enabled = false;
        config.volumetric_lighting.enabled = true;
        let settings =
            AtmosphereSettings::from_config(config.volumetric_fog, config.volumetric_lighting);
        let frame = valid_frame();

        assert_eq!(settings.lighting_medium_density, 0.0000025);
        assert!((0.740..0.742).contains(&settings.estimated_horizontal_transmittance(frame)));
    }

    #[test]
    fn fog_options_map_to_the_fixed_atmosphere_abi() {
        let mut config = EmbeddedEffectsConfig::default();
        config.volumetric_fog.enabled = true;
        config.volumetric_fog.quality = AtmosphereQuality::Ultra;
        config.volumetric_fog.density = 0.00003;
        config.volumetric_fog.height_density = 0.00004;
        config.volumetric_fog.height_falloff = 0.0002;
        config.volumetric_fog.base_height = 345.0;
        config.volumetric_fog.max_distance = 90_000.0;
        config.volumetric_fog.scattering_albedo = 0.75;
        config.volumetric_fog.noise_amount = 0.5;
        config.volumetric_fog.noise_scale = 0.001;
        config.volumetric_fog.noise_speed = 0.04;
        config.volumetric_fog.temporal_stability = 0.8;
        config.volumetric_fog.debug_view = 8;
        let sources = shaders::merge_embedded_sources(&config, Vec::new());
        let source = sources
            .iter()
            .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::VolumetricFog))
            .expect("volumetric fog source");
        let settings = AtmosphereSettings::from_sources(Some(source), None);

        assert!(settings.fog_enabled);
        assert_eq!(settings.quality, AtmosphereQuality::Ultra);
        assert_eq!(settings.density, 0.00003);
        assert_eq!(settings.height_density, 0.00004);
        assert_eq!(settings.height_falloff, 0.0002);
        assert_eq!(settings.base_height, 345.0);
        assert_eq!(settings.max_distance, 90_000.0);
        assert_eq!(settings.scattering_albedo, 0.75);
        assert_eq!(settings.noise_amount, 0.5);
        assert_eq!(settings.noise_scale, 0.001);
        assert_eq!(settings.noise_speed, 0.04);
        assert_eq!(settings.temporal_stability, 0.8);
        assert_eq!(settings.debug_view, 8);
        assert!(settings.requires_depth());
        assert!(settings.requires_world_color());

        let choices = source
            .options
            .iter()
            .find(|option| option.key == "debug_view")
            .and_then(|option| option.choices)
            .expect("debug choices");
        assert_eq!(choices.len(), 9);
        assert_eq!(choices[6], "Optical depth / transmittance");
        assert_eq!(choices[7], "Integrated scattering");
        assert_eq!(choices[8], "Bilateral acceptance");
    }

    #[test]
    fn lighting_options_map_to_the_fixed_atmosphere_abi() {
        let mut config = EmbeddedEffectsConfig::default();
        config.volumetric_fog.enabled = false;
        config.volumetric_lighting.enabled = true;
        config.volumetric_lighting.intensity = 2.5;
        config.volumetric_lighting.medium_density = 0.00004;
        config.volumetric_lighting.max_distance = 88_000.0;
        config.volumetric_lighting.anisotropy = 0.4;
        config.volumetric_lighting.shaft_strength = 0.7;
        config.volumetric_lighting.sun_disk_boost = 3.0;
        config.volumetric_lighting.shaft_quality = AtmosphereQuality::Ultra;
        config.volumetric_lighting.local_lights_enabled = true;
        config.volumetric_lighting.local_lights_intensity = 1.75;
        config.volumetric_lighting.local_lights_quality = AtmosphereQuality::Performance;
        config.volumetric_lighting.debug_view = 8;
        let sources = shaders::merge_embedded_sources(&config, Vec::new());
        let source = sources
            .iter()
            .find(|source| {
                source.embedded_effect_kind() == Some(EmbeddedEffectKind::VolumetricLighting)
            })
            .expect("volumetric lighting source");
        let settings = AtmosphereSettings::from_sources(None, Some(source));

        assert!(!settings.fog_enabled);
        assert!(settings.lighting_enabled);
        assert_eq!(settings.lighting_intensity, 2.5);
        assert_eq!(settings.lighting_medium_density, 0.00004);
        assert_eq!(settings.max_distance, 88_000.0);
        assert_eq!(settings.anisotropy, 0.4);
        assert_eq!(settings.shaft_strength, 0.7);
        assert_eq!(settings.sun_disk_boost, 3.0);
        assert_eq!(settings.shaft_quality, AtmosphereQuality::Ultra);
        assert_eq!(settings.quality, AtmosphereQuality::Ultra);
        assert!(settings.local_lights_enabled);
        assert_eq!(settings.local_lights_intensity, 1.75);
        assert_eq!(
            settings.local_lights_quality,
            AtmosphereQuality::Performance
        );
        assert_eq!(settings.lighting_debug_view(), 8);
        assert!(settings.requires_depth());
        assert!(settings.requires_world_color());

        let choices = source
            .options
            .iter()
            .find(|option| option.key == "debug_view")
            .and_then(|option| option.choices)
            .expect("lighting debug choices");
        assert_eq!(choices.len(), 9);
        assert_eq!(choices[1], "Shaft mask");
        assert_eq!(choices[5], "Combined acceptance");
        assert_eq!(choices[6], "Local-light bounds");
        assert_eq!(choices[7], "Local shadow visibility");
        assert_eq!(choices[8], "Local scattering");
    }

    #[test]
    fn local_lights_are_independent_from_directional_sun_lighting() {
        let mut config = EmbeddedEffectsConfig::default();
        config.volumetric_fog.enabled = false;
        config.volumetric_lighting.enabled = false;
        config.volumetric_lighting.local_lights_enabled = true;
        config.volumetric_lighting.local_lights_intensity = 1.0;
        let settings =
            AtmosphereSettings::from_config(config.volumetric_fog, config.volumetric_lighting);

        assert!(!settings.lighting_enabled);
        assert!(settings.local_lights_enabled);
        assert!(settings.requires_depth());
        assert!(settings.requires_world_color());
        assert_eq!(
            fog_integration_gate(valid_frame(), settings, false),
            FogIntegrationGate::NoReadyContribution,
        );
        assert_eq!(
            fog_integration_gate(valid_frame(), settings, true),
            FogIntegrationGate::Ready,
        );
    }

    #[test]
    fn local_only_base_pass_preserves_identity_transmittance() {
        let mut local = settings();
        local.fog_enabled = false;
        local.lighting_enabled = false;
        local.local_lights_enabled = true;
        let contributions = resolve_contributions(valid_frame(), local);

        assert!(!contributions.fog);
        assert!(!contributions.lighting_ready());
        assert_eq!(base_medium_density(local, contributions), 0.0);
    }

    #[test]
    fn lighting_debug_selection_has_explicit_precedence() {
        assert_eq!(selected_debug_view(0, 0), 0);
        assert_eq!(selected_debug_view(7, 0), 7);
        assert_eq!(selected_debug_view(7, 2), 10);
        assert_eq!(selected_debug_view(99, 99), 16);
    }

    #[test]
    fn henyey_greenstein_is_normalized_finite_and_directional() {
        let isotropic = 1.0 / (4.0 * core::f32::consts::PI);
        assert!((henyey_greenstein(-0.75, 0.0) - isotropic).abs() < 0.000001);
        assert!(henyey_greenstein(1.0, 0.65) > henyey_greenstein(0.0, 0.65));
        assert!(henyey_greenstein(0.0, 0.65) > henyey_greenstein(-1.0, 0.65));
        assert!((henyey_greenstein(0.6, -0.7) - henyey_greenstein(-0.6, 0.7)).abs() < 0.000001);
        assert!((directional_phase_response(0.25, 0.0) - 1.0).abs() < 0.000001);
        assert!(directional_phase_response(1.0, 0.65) > 10.0);

        let steps = 20_000;
        let delta_mu = 2.0 / steps as f32;
        for anisotropy in [-0.8, -0.4, 0.0, 0.65, 0.9] {
            let mut integral = 0.0;
            for index in 0..steps {
                let mu = -1.0 + (index as f32 + 0.5) * delta_mu;
                let phase = henyey_greenstein(mu, anisotropy);
                assert!(phase.is_finite() && phase >= 0.0);
                integral += phase * 2.0 * core::f32::consts::PI * delta_mu;
            }
            assert!((integral - 1.0).abs() < 0.001, "g={anisotropy}: {integral}");
        }
    }

    #[test]
    fn captured_camera_projection_handles_rotation_jitter_and_visibility() {
        let frame = valid_frame();
        let center = project_sun_from_captured_camera(frame.camera, [1.0, 0.0, 0.0]);
        assert_eq!(center.uv, [0.5, 0.5]);
        assert_eq!(center.facing, 1.0);
        assert!(center.on_screen && center.edge_fade == 1.0);

        let mut rotated = frame.camera;
        rotated.world_transform.rotation = [[0.0, -1.0, 0.0], [1.0, 0.0, 0.0], [0.0, 0.0, 1.0]];
        let rotated_center = project_sun_from_captured_camera(rotated, [0.0, 1.0, 0.0]);
        assert_eq!(rotated_center.uv, [0.5, 0.5]);
        assert!(rotated_center.on_screen);

        let mut asymmetric = frame.camera;
        asymmetric.frustum_left = -0.9;
        asymmetric.frustum_right = 1.1;
        let shifted = project_sun_from_captured_camera(asymmetric, [1.0, 0.0, 0.0]);
        assert!((shifted.uv[0] - 0.45).abs() < 0.000001);
        asymmetric.frustum_left += 0.02;
        asymmetric.frustum_right += 0.02;
        let jittered = project_sun_from_captured_camera(asymmetric, [1.0, 0.0, 0.0]);
        assert!((jittered.uv[0] - 0.44).abs() < 0.000001);

        let behind = project_sun_from_captured_camera(frame.camera, [-1.0, 0.0, 0.0]);
        assert_eq!(behind.facing, -1.0);
        assert!(!behind.on_screen);
        let off_screen = project_sun_from_captured_camera(frame.camera, [1.0, 0.0, 2.0]);
        assert!(off_screen.facing > 0.0);
        assert!(!off_screen.on_screen);
    }

    #[test]
    fn directional_lighting_fades_continuously_and_stops_at_the_screen_edge() {
        let mut frame = valid_frame();
        frame.sky = Some(valid_sky([1.0, 0.0, 0.0]));
        let centered = resolve_contributions(frame, {
            let mut settings = settings();
            settings.fog_enabled = false;
            settings.lighting_enabled = true;
            settings
        })
        .light
        .expect("centered sun");

        let normalize = |direction: [f32; 3]| {
            let length = direction
                .into_iter()
                .map(|value| value * value)
                .sum::<f32>()
                .sqrt();
            direction.map(|value| value / length)
        };
        frame.sky = Some(valid_sky(normalize([1.0, 0.0, 0.98])));
        let near_edge = resolve_directional_light(frame).expect("sun just inside edge");
        frame.sky = Some(valid_sky(normalize([1.0, 0.0, 1.0])));
        let at_edge = resolve_directional_light(frame);
        frame.sky = Some(valid_sky(normalize([1.0, 0.0, 1.02])));
        let outside = resolve_directional_light(frame);

        assert!(centered.daylight > near_edge.daylight);
        assert!(near_edge.daylight > 0.0);
        assert!(at_edge.is_none());
        assert!(outside.is_none());
    }

    #[test]
    fn shaft_modulation_and_disk_boost_are_bounded_and_local() {
        for strength in [0.0, 0.25, 0.5, 1.0] {
            for field in [0.0, 0.3, 1.0] {
                let visibility = bounded_shaft_visibility(field, 0.8, strength);
                assert!((0.0..=1.0).contains(&visibility));
                if strength == 0.0 {
                    assert_eq!(visibility, 1.0);
                }
            }
        }
        assert_eq!(bounded_shaft_visibility(0.0, 0.0, 1.0), 1.0);
        let one_blocker_in_forty = shaft_visibility_from_blocked_fraction(1.0 / 40.0, 1.0, 1.0);
        assert!((0.73..0.75).contains(&one_blocker_in_forty));
        assert_eq!(shaft_visibility_from_blocked_fraction(1.0, 1.0, 0.0), 1.0);
        assert!(shaft_visibility_from_blocked_fraction(0.1, 1.0, 1.0) < 0.31);

        let base = [2.0, 1.5, 1.0];
        let delta = [3.0, 1.0, 0.5];
        assert_eq!(directional_radiance(base, delta, 8.0, 0.0), base);
        assert_eq!(directional_radiance(base, delta, 0.0, 1.0), base);
        let boosted = directional_radiance(base, delta, 8.0, 1.0);
        assert_eq!(boosted, [26.0, 9.5, 5.0]);
        assert!(
            boosted
                .into_iter()
                .all(|value| value.is_finite() && value >= 0.0)
        );
    }

    #[test]
    fn calibrated_default_produces_visible_directional_scattering() {
        let density = 0.000002_f32;
        let distance = 10_000.0_f32;
        let scatter_amount = 1.0 - (-density * distance).exp();
        let forward = directional_phase_response(1.0, 0.65) * scatter_amount;
        let side = directional_phase_response(0.0, 0.65) * scatter_amount;

        assert!(forward > 0.25);
        assert!(side > 0.005);
        assert!(forward > side * 30.0);
        assert!(forward * 8.0 > forward);
    }

    #[test]
    fn fog_cannot_reduce_directional_scattering() {
        let lighting_only = directional_scatter_amount(1.0, 0.9, 0.000002, 10_000.0);
        let thin_fog = directional_scatter_amount(0.98, 0.9, 0.000002, 10_000.0);
        let dense_fog = directional_scatter_amount(0.35, 0.9, 0.000002, 10_000.0);

        assert!(lighting_only > 0.0);
        assert!(thin_fog >= lighting_only);
        assert!(dense_fog > thin_fog);
    }

    #[test]
    fn fog_and_directional_lighting_contributions_are_independent() {
        let frame = valid_frame();
        let fog_only = settings();
        let contributions = resolve_contributions(frame, fog_only);
        assert!(contributions.fog);
        assert!(!contributions.lighting_ready());
        assert_eq!(
            fog_integration_gate(frame, fog_only, false),
            FogIntegrationGate::Ready
        );

        let mut lighting_only = settings();
        lighting_only.fog_enabled = false;
        lighting_only.lighting_enabled = true;
        assert_eq!(
            fog_integration_gate(frame, lighting_only, false),
            FogIntegrationGate::NoReadyContribution
        );
        let mut sun_frame = frame;
        sun_frame.sky = Some(valid_sky([1.0, 0.0, 0.0]));
        let contributions = resolve_contributions(sun_frame, lighting_only);
        assert!(!contributions.fog);
        assert!(contributions.lighting_ready());
        assert_eq!(
            fog_integration_gate(sun_frame, lighting_only, false),
            FogIntegrationGate::Ready
        );
        assert_eq!(
            lighting_only.effective_uniform_density(false),
            lighting_only.lighting_medium_density
        );
        assert_eq!(lighting_only.effective_scattering_albedo(false), 1.0);

        let mut combined = settings();
        combined.lighting_enabled = true;
        combined.lighting_medium_density = 0.0009;
        assert_eq!(combined.effective_uniform_density(true), combined.density);
        assert_eq!(
            combined.effective_scattering_albedo(true),
            combined.scattering_albedo
        );
        let missing_sun = resolve_contributions(frame, combined);
        assert!(missing_sun.fog);
        assert!(!missing_sun.lighting_ready());
        assert_eq!(
            fog_integration_gate(frame, combined, false),
            FogIntegrationGate::Ready
        );
        let ready = resolve_contributions(sun_frame, combined);
        assert!(ready.fog && ready.lighting_ready());
    }

    #[test]
    fn draw_outcomes_report_whether_the_atmosphere_drew() {
        assert!(!AtmosphereDrawOutcome::Skipped.drew());
        assert!(!AtmosphereDrawOutcome::NoVisibleContribution.drew());
        assert!(!AtmosphereDrawOutcome::Skipped.completes_pre_alpha());
        assert!(AtmosphereDrawOutcome::NoVisibleContribution.completes_pre_alpha());
        assert!(AtmosphereDrawOutcome::Composed.drew());
        assert!(AtmosphereDrawOutcome::ComposedWithLighting.drew());
        assert!(AtmosphereDrawOutcome::DebugDrawn.drew());
        assert!(AtmosphereDrawOutcome::LightingDebugDrawn.drew());
    }

    #[test]
    fn integration_gate_requires_current_exterior_above_water_contract() {
        let settings = settings();
        let mut frame = valid_frame();
        assert_eq!(
            fog_integration_gate(frame, settings, false),
            FogIntegrationGate::Ready
        );

        frame.underwater.frame_epoch = 6;
        assert_eq!(
            fog_integration_gate(frame, settings, false),
            FogIntegrationGate::UnderwaterUnknown
        );
        frame.underwater.frame_epoch = 7;
        frame.underwater.underwater = true;
        assert_eq!(
            fog_integration_gate(frame, settings, false),
            FogIntegrationGate::Underwater
        );
        frame.underwater.underwater = false;
        frame.material_state.is_exterior = false;
        assert_eq!(
            fog_integration_gate(frame, settings, false),
            FogIntegrationGate::Interior
        );
    }

    #[test]
    fn integration_gate_fails_closed_for_each_required_contract_group() {
        let mut settings = settings();
        let mut frame = valid_frame();

        settings.fog_enabled = false;
        assert_eq!(
            fog_integration_gate(frame, settings, false),
            FogIntegrationGate::Disabled
        );
        settings.fog_enabled = true;
        settings.density = 0.0;
        settings.height_density = 0.0;
        assert_eq!(
            fog_integration_gate(frame, settings, false),
            FogIntegrationGate::EmptyMedium
        );
        settings.height_density = 0.00002;

        frame.depth = DepthFrame::none();
        assert_eq!(
            fog_integration_gate(frame, settings, false),
            FogIntegrationGate::MissingDepthContract
        );
        frame = valid_frame();
        frame.camera.world_transform.available = false;
        assert_eq!(
            fog_integration_gate(frame, settings, false),
            FogIntegrationGate::MissingWorldTransform
        );
        frame = valid_frame();
        frame.material_state.exterior_known = false;
        assert_eq!(
            fog_integration_gate(frame, settings, false),
            FogIntegrationGate::ExteriorUnknown
        );
        frame = valid_frame();
        frame.environment.fog_available = false;
        assert_eq!(
            fog_integration_gate(frame, settings, false),
            FogIntegrationGate::NoReadyContribution
        );
    }

    #[test]
    fn production_composition_requires_current_fp16_color_and_alpha_contract() {
        use libpsycho::os::windows::directx9::{
            D3DFMT_A8R8G8B8, D3DFMT_A16B16G16R16F, D3DSURFACE_DESC, USAGE_RENDER_TARGET,
        };

        let mut settings = settings();
        let mut desc = D3DSURFACE_DESC {
            Format: D3DFMT_A16B16G16R16F,
            Usage: USAGE_RENDER_TARGET,
            Width: 1920,
            Height: 1080,
            ..D3DSURFACE_DESC::default()
        };
        assert_eq!(
            fog_composition_gate(
                FogIntegrationGate::Ready,
                true,
                true,
                &desc,
                settings,
                true,
                true,
            ),
            FogCompositionGate::Ready
        );

        assert_eq!(
            fog_composition_gate(
                FogIntegrationGate::Ready,
                true,
                false,
                &desc,
                settings,
                true,
                true,
            ),
            FogCompositionGate::MissingWorldColor
        );
        desc.Format = D3DFMT_A8R8G8B8;
        assert_eq!(
            fog_composition_gate(
                FogIntegrationGate::Ready,
                true,
                true,
                &desc,
                settings,
                true,
                true,
            ),
            FogCompositionGate::UnsupportedWorldTarget
        );
        desc.Format = D3DFMT_A16B16G16R16F;
        assert_eq!(
            fog_composition_gate(
                FogIntegrationGate::Ready,
                true,
                true,
                &desc,
                settings,
                true,
                false,
            ),
            FogCompositionGate::TaaAlphaUnavailable
        );
        settings.debug_view = 8;
        assert_eq!(
            fog_composition_gate(
                FogIntegrationGate::Ready,
                true,
                true,
                &desc,
                settings,
                true,
                true,
            ),
            FogCompositionGate::DebugView
        );
    }

    #[test]
    fn medium_color_prefers_fog_and_guards_the_horizon_fallback() {
        let mut frame = valid_frame();
        frame.sky = Some(NativeSkyFrame {
            sky_upper: [0.0; 3],
            sky_lower: [0.0; 3],
            horizon: [0.8, 0.7, 0.6],
            sun_light: [0.0; 3],
            sun_disk: [0.0; 3],
            sun_direction: [0.0; 3],
            daylight: 1.0,
            game_hour: 12.0,
            is_exterior: true,
            reversed_depth: true,
        });
        let fog = resolve_medium_color(frame).expect("active fog color");
        assert_eq!(
            fog.linear_rgb,
            linearize_native_color(frame.environment.fog_color).expect("finite fog")
        );

        frame.environment.fog_available = false;
        let horizon = resolve_medium_color(frame).expect("exterior horizon fallback");
        assert_eq!(
            horizon.linear_rgb,
            linearize_native_color(frame.sky.expect("sky").horizon).expect("finite horizon")
        );

        frame.material_state.is_exterior = false;
        assert!(resolve_medium_color(frame).is_none());
    }

    #[test]
    fn native_color_linearization_rejects_non_finite_values() {
        assert_eq!(
            linearize_native_color([0.0, 1.0, -1.0]),
            Some([0.0, 1.0, 0.0])
        );
        assert!(linearize_native_color([f32::NAN, 0.0, 0.0]).is_none());
        assert!(linearize_native_color([f32::INFINITY, 0.0, 0.0]).is_none());
        assert!(linearize_native_color([f32::MAX, 0.0, 0.0]).is_none());
        let threshold = linearize_native_color([0.04045; 3]).expect("finite color");
        assert!((threshold[0] - 0.003130805).abs() < 0.000001);
    }

    #[test]
    fn extended_srgb_round_trips_signed_nominal_and_overbright_values() {
        for value in [-0.25, -0.01, 0.0, 0.0031308, 0.04045, 0.5, 1.0, 4.0] {
            let encoded = encode_extended_srgb(value);
            let decoded = decode_extended_srgb(encoded);
            assert!(
                (decoded - value).abs() <= 0.00001 * value.abs().max(1.0),
                "{value} -> {encoded} -> {decoded}",
            );
        }
    }

    #[test]
    fn layered_key_keeps_foreground_and_background_inside_a_mixed_interval() {
        assert_eq!(layered_tap_weight(100.0, 100.0, 100.0, 2), 1.0);
        assert_eq!(layered_tap_weight(100.0, 100.0, 10_000.0, 2), 1.0);
        assert_eq!(layered_tap_weight(10_000.0, 100.0, 10_000.0, 2), 1.0);
        assert_eq!(layered_tap_weight(5_050.0, 5_000.0, 5_100.0, 2), 1.0);
        assert!(layered_tap_weight(7_000.0, 5_000.0, 5_100.0, 4) <= f32::EPSILON);
    }

    #[test]
    fn mixed_foreground_sky_cell_cannot_toggle_sky_fog_off() {
        let foreground = 100.0;
        let sky = 10_000.0;
        assert_eq!(layered_tap_weight(sky, foreground, sky, 2), 1.0);
        assert_eq!(atmosphere_layer_blend(sky, foreground, sky), 1.0);
        assert_eq!(layered_tap_weight(sky, sky, sky, 2), 1.0);
        assert_eq!(atmosphere_layer_blend(sky, sky, sky), 0.0);
    }

    #[test]
    fn deterministic_noise_has_stable_dimensions_and_content() {
        let first = density_noise_pixels();
        let second = density_noise_pixels();
        assert_eq!(first.len(), 64 * 64);
        assert_eq!(first, second);
        assert!(first.windows(2).any(|window| window[0] != window[1]));
    }

    #[test]
    fn option_component_uses_register_relative_storage() {
        let constants = [[1.0, 2.0, 3.0, 4.0], [5.0, 6.0, 7.0, 8.0]];
        assert_eq!(option_component(Some(&constants), 1, 2, 9.0), 7.0);
        assert_eq!(option_component(Some(&constants), 3, 0, 9.0), 9.0);
    }

    #[test]
    fn local_ray_sphere_interval_handles_miss_inside_behind_and_clipping_edges() {
        let origin = [0.0, 0.0, 0.0];
        let forward = [1.0, 0.0, 0.0];
        assert_eq!(
            ray_sphere_interval(origin, forward, [100.0, 0.0, 0.0], 10.0, 1_000.0, 1_000.0),
            Some((90.0, 110.0)),
        );
        assert_eq!(
            ray_sphere_interval(origin, forward, [0.0, 0.0, 0.0], 10.0, 1_000.0, 1_000.0),
            Some((0.0, 10.0)),
        );
        assert!(
            ray_sphere_interval(origin, forward, [-100.0, 0.0, 0.0], 10.0, 1_000.0, 1_000.0)
                .is_none()
        );
        assert!(
            ray_sphere_interval(origin, forward, [100.0, 20.0, 0.0], 10.0, 1_000.0, 1_000.0)
                .is_none()
        );
        assert_eq!(
            ray_sphere_interval(origin, forward, [100.0, 0.0, 0.0], 10.0, 95.0, 1_000.0),
            Some((90.0, 95.0)),
        );
        assert!(
            ray_sphere_interval(origin, forward, [100.0, 0.0, 0.0], 0.0, 1_000.0, 1_000.0)
                .is_none()
        );
    }

    #[test]
    fn local_scissor_is_conservative_and_fails_closed_offscreen() {
        let camera = valid_frame().camera;
        let centered = local_light_scissor(camera, 960, 540, [100.0, 0.0, 0.0], 10.0, 10_000.0)
            .expect("centered sphere");
        assert!(centered.left < 480 && centered.right > 480);
        assert!(centered.top < 270 && centered.bottom > 270);

        let near = local_light_scissor(camera, 960, 540, [5.0, 0.0, 0.0], 10.0, 10_000.0)
            .expect("near-plane sphere");
        assert_eq!(
            (near.left, near.top, near.right, near.bottom),
            (0, 0, 960, 540)
        );
        assert!(
            local_light_scissor(camera, 960, 540, [-100.0, 0.0, 0.0], 10.0, 10_000.0).is_none()
        );
        assert!(
            local_light_scissor(camera, 960, 540, [100.0, 0.0, 500.0], 10.0, 10_000.0).is_none()
        );
        assert!(
            local_light_scissor(camera, 960, 540, [20_000.0, 0.0, 0.0], 10.0, 1_000.0).is_none()
        );
    }

    #[test]
    fn shadowless_light_count_does_not_increase_draw_count() {
        assert_eq!(local_light_draw_count(0, 0), 0);
        assert_eq!(local_light_draw_count(1, 0), 2);
        assert_eq!(local_light_draw_count(2, 0), 2);
        assert_eq!(local_light_draw_count(4, 0), 2);
        assert_eq!(local_light_draw_count(1, 1), 4);
        assert_eq!(local_light_draw_count(1, 3), 8);
        assert_eq!(local_light_draw_count(0, 4), 8);
    }

    #[test]
    fn batched_scissor_conservatively_contains_every_light_rectangle() {
        let first = super::ScissorRect {
            left: 100,
            top: 40,
            right: 300,
            bottom: 240,
        };
        let second = super::ScissorRect {
            left: 20,
            top: 80,
            right: 220,
            bottom: 400,
        };
        assert_eq!(
            union_scissor(Some(first), second),
            super::ScissorRect {
                left: 20,
                top: 40,
                right: 300,
                bottom: 400,
            }
        );
        assert_eq!(union_scissor(None, first), first);
    }

    #[test]
    fn batched_light_constants_match_the_fixed_shader_register_abi() {
        let mut constants = [[0.0; 4]; 21];
        for index in 0..4 {
            write_batched_light_constants(
                &mut constants,
                index,
                crate::fnv_local_lights::LocalLightValues {
                    position: [index as f32 + 1.0, 2.0, 3.0],
                    color: [4.0, index as f32 + 5.0, 6.0],
                    radius: 7.0,
                },
                1.5,
            );
            assert_eq!(constants[8 + index], [index as f32 + 1.0, 2.0, 3.0, 7.0]);
            assert_eq!(constants[12 + index], [4.0, index as f32 + 5.0, 6.0, 1.5]);
        }
        assert_eq!(constants[16], [0.0; 4]);
    }

    #[test]
    fn local_light_layer_rebinds_inputs_after_target_hazard_clear() {
        let source = include_str!("atmosphere.rs");
        let batch_start = source
            .find("fn draw_local_light_batch(")
            .expect("local-light batch function");
        let layer_start = source
            .find("fn draw_local_light_layer(")
            .expect("local-light layer function");
        let composition_start = source
            .find("fn draw_composition(")
            .expect("composition function");
        let batch = &source[batch_start..layer_start];
        let layer = &source[layer_start..composition_start];

        assert!(!batch.contains("set_texture("));
        assert!(!batch.contains("set_raw_base_texture("));

        let target_bind = layer.find("bind_target(").expect("target bind");
        let depth_bind = layer.find("set_texture(0").expect("depth bind");
        let noise_bind = layer.find("set_texture(1").expect("noise bind");
        let shadow_bind = layer
            .find("set_raw_base_texture(2")
            .expect("native-shadow bind");
        let draw = layer.find("draw_quad(").expect("local-light draw");
        assert!(target_bind < depth_bind);
        assert!(target_bind < noise_bind);
        assert!(target_bind < shadow_bind);
        assert!(depth_bind < draw);
        assert!(noise_bind < draw);
        assert!(shadow_bind < draw);
    }

    #[test]
    fn native_shadow_projection_preserves_row_dots_y_flip_and_compare_direction() {
        let matrix = [
            [1.0, 0.0, 0.0, 0.0],
            [0.0, 1.0, 0.0, 0.0],
            [0.0, 0.0, 1.0, 0.0],
            [0.0, 0.0, 0.0, 2.0],
        ];
        let (uv, depth) = project_native_shadow(matrix, [0.5, -0.5, 0.25]).expect("projection");
        assert_eq!(uv, [0.625, 0.625]);
        assert_eq!(depth, 0.25);
        let r32_bias = crate::fnv_local_lights::ShadowTextureFormat::R32F.bias();
        let a8_bias = crate::fnv_local_lights::ShadowTextureFormat::A8R8G8B8.bias();
        assert!(depth < (depth - r32_bias * 0.5) + r32_bias);
        assert!(!(depth < (depth - r32_bias * 2.0) + r32_bias));
        assert!(a8_bias >= 1.0 / 255.0);
        assert!(project_native_shadow(matrix, [f32::NAN, 0.0, 0.0]).is_none());
        let behind = [matrix[0], matrix[1], matrix[2], [0.0, 0.0, 0.0, -1.0]];
        assert!(project_native_shadow(behind, [0.0; 3]).is_none());
    }

    #[test]
    fn deterministic_local_integration_is_energy_stable_across_quality_tiers() {
        let analytic = 1.0 - (-0.0002_f32 * 2_000.0).exp();
        for samples in [4, 6, 10] {
            let integrated = integrated_uniform_scatter(0.0002, 2_000.0, samples);
            assert!((integrated - analytic).abs() < 0.00001, "samples={samples}");
            assert!(integrated.is_finite() && integrated >= 0.0 && integrated <= 1.0);
        }
    }

    #[test]
    fn interior_medium_is_enabled_only_by_a_ready_local_light() {
        let mut frame = valid_frame();
        frame.material_state.is_exterior = false;
        frame.environment.fog_available = false;
        frame.sky = None;
        let mut local = settings();
        local.fog_enabled = false;
        local.lighting_enabled = false;
        local.local_lights_enabled = true;
        assert_eq!(
            fog_integration_gate(frame, local, false),
            FogIntegrationGate::Interior,
        );
        assert_eq!(
            fog_integration_gate(frame, local, true),
            FogIntegrationGate::Ready,
        );
        frame.underwater.underwater = true;
        assert_eq!(
            fog_integration_gate(frame, local, true),
            FogIntegrationGate::Underwater,
        );
    }
}

#[cfg(test)]
mod shader_compile_tests {
    use super::{
        COMPOSE_SHADER, DEBUG_SHADER, DEPTH_REDUCE_SHADER, INTEGRATE_SHADER, LOCAL_LIGHT_SHADER,
        SHAFT_MASK_SHADER, SHAFT_RADIAL_SHADER, depth_reduce_shader_source,
        integration_shader_source, local_light_shader_source, shaft_radial_shader_source,
        view_to_world_rows,
    };
    use crate::backend::{CameraFrame, CameraTransformFrame};

    #[test]
    fn atmosphere_foundation_shaders_compile() {
        for scale in [2, 4] {
            let source = if scale == 2 {
                DEPTH_REDUCE_SHADER.to_vec()
            } else {
                depth_reduce_shader_source(scale)
            };
            crate::shaders::assert_hlsl_compiles(
                &format!("atmosphere_depth_reduce.hlsl:{scale}"),
                &source,
                "ps_3_0",
            );
        }
        for samples in [8, 12, 20] {
            crate::shaders::assert_hlsl_compiles(
                &format!("atmosphere_integrate.hlsl:{samples}"),
                &integration_shader_source(samples),
                "ps_3_0",
            );
        }
        crate::shaders::assert_hlsl_compiles(
            "atmosphere_shaft_mask.hlsl",
            SHAFT_MASK_SHADER,
            "ps_3_0",
        );
        for samples in [24, 40, 56] {
            crate::shaders::assert_hlsl_compiles(
                &format!("atmosphere_shaft_radial.hlsl:{samples}"),
                &shaft_radial_shader_source(samples),
                "ps_3_0",
            );
        }
        for (samples, noise) in [(4, false), (6, true), (10, true)] {
            for batch_size in 1..=4 {
                crate::shaders::assert_hlsl_compiles(
                    &format!("atmosphere_local_light.hlsl:{samples}:shadowless:batch={batch_size}"),
                    &local_light_shader_source(samples, batch_size, noise, false),
                    "ps_3_0",
                );
            }
            crate::shaders::assert_hlsl_compiles(
                &format!("atmosphere_local_light.hlsl:{samples}:shadowed"),
                &local_light_shader_source(samples, 1, noise, true),
                "ps_3_0",
            );
        }
        crate::shaders::assert_hlsl_compiles("atmosphere_compose.hlsl", COMPOSE_SHADER, "ps_3_0");
        crate::shaders::assert_hlsl_compiles("atmosphere_debug.hlsl", DEBUG_SHADER, "ps_3_0");
    }

    #[test]
    fn atmosphere_composition_uses_depth_matched_near_and_far_layers() {
        let integrate = std::str::from_utf8(INTEGRATE_SHADER).expect("integration shader source");
        let compose = std::str::from_utf8(COMPOSE_SHADER).expect("composition shader source");
        assert!(integrate.contains("lerp(encodedDepth.x, encodedDepth.y"));
        assert!(compose.contains("sampler2D NearAtmosphere : register(s3)"));
        assert!(compose.contains("sampler2D FarAtmosphere : register(s4)"));
        assert!(compose.contains("clamp(fullDistance, nearest, farthest)"));
        assert!(!compose.contains("abs(fullDistance - nearest)"));
        assert!(compose.contains("return float4(encodedOutput, source.a)"));
    }

    #[test]
    fn directional_shader_abi_is_fixed_and_deterministic() {
        let integrate = std::str::from_utf8(INTEGRATE_SHADER).expect("integration shader source");
        let mask = std::str::from_utf8(SHAFT_MASK_SHADER).expect("shaft mask source");
        let radial = std::str::from_utf8(SHAFT_RADIAL_SHADER).expect("shaft radial source");

        assert!(integrate.contains("ShaftVisibility : register(s2)"));
        assert!(integrate.contains("LightingData : register(c10)"));
        assert!(integrate.contains("SunDirection : register(c11)"));
        assert!(integrate.contains("SunColor : register(c12)"));
        assert!(integrate.contains("SunDiskDelta : register(c13)"));
        assert!(integrate.contains("LightingMediumData : register(c14)"));
        assert!(integrate.contains("HenyeyGreenstein"));
        assert!(integrate.contains("HenyeyGreenstein(mu, LightingData.y) * FourPi"));
        assert!(integrate.contains("float directionalScatterAmount = max("));
        assert!(integrate.contains("1.0f - exp(-lightingOpticalDepth)"));
        assert!(integrate.contains("* directionalScatterAmount"));
        assert_eq!(
            integrate
                .matches("HeterogeneousCorrection(distance")
                .count(),
            1
        );
        assert!(radial.contains("#define ATMOSPHERE_SHAFT_SAMPLE_COUNT"));
        assert!(radial.contains("index < ATMOSPHERE_SHAFT_SAMPLE_COUNT"));
        assert!(radial.contains("exp(-12.0f * blockedFraction)"));
        assert!(radial.contains("lerp(1.0f, field, influence)"));
        assert!(!radial.contains("frame"));
        assert!(!radial.contains("Frame"));
        assert!(!mask.contains("frame"));
        assert!(!mask.contains("Frame"));
    }

    #[test]
    fn local_light_shader_has_independent_shadowless_and_native_shadow_contracts() {
        let source = std::str::from_utf8(LOCAL_LIGHT_SHADER).expect("local-light shader source");
        assert!(source.contains("ReducedDepth : register(s0)"));
        assert!(source.contains("DensityNoise : register(s1)"));
        assert!(source.contains("NativeShadow : register(s2)"));
        assert!(source.contains("#if LOCAL_LIGHT_USE_NATIVE_SHADOW"));
        assert!(source.contains("LocalPositionRadius0 : register(c8)"));
        assert!(source.contains("LocalPositionRadius3 : register(c11)"));
        assert!(source.contains("LocalColorIntensity0 : register(c12)"));
        assert!(source.contains("LocalColorIntensity3 : register(c15)"));
        assert!(source.contains("LocalControl : register(c16)"));
        assert!(source.contains("ShadowMatrix0 : register(c17)"));
        assert!(source.contains("ShadowMatrix3 : register(c20)"));
        assert!(source.contains("dot(ShadowMatrix0, homogeneous)"));
        assert!(source.contains("0.5f * shadowPosition.x / shadowPosition.w + 0.5f"));
        assert!(source.contains("0.5f - 0.5f * shadowPosition.y / shadowPosition.w"));
        assert!(source.contains("shadowPosition.z < shadowDepth + LocalControl.x"));
        assert!(source.contains("#else\n\treturn 1.0f;\n#endif"));
        assert!(source.contains("sampleIndex < LOCAL_LIGHT_SAMPLE_COUNT"));
        assert!(source.contains("#if LOCAL_LIGHT_BATCH_SIZE >= 4"));
        assert!(source.contains("result += IntegrateLocalLight("));
        assert!(!source.contains("[localIndex]"));
        assert!(!source.contains("for (int localIndex"));
        assert!(source.contains("return float3(0.10f, 0.55f, 1.0f)"));
        assert!(source.contains("lerp(shadowed, visible, visibility)"));
        assert!(source.contains("scattering / (scattering + 0.01f)"));
        assert!(source.contains("denominator * sqrt(denominator)"));
        assert!(source.contains("float stepTransmittance = exp(-stepOpticalDepth)"));
        assert!(source.contains("cameraTransmittance *= stepTransmittance"));
        assert_eq!(source.matches("exp(-stepOpticalDepth)").count(), 1);
        assert!(!source.contains("pow(denominator"));
        assert!(!source.contains("frameIndex"));
        assert!(!source.contains("FrameIndex"));
        for (samples, noise) in [(4, false), (6, true), (10, true)] {
            for batch_size in 1..=4 {
                let variant =
                    String::from_utf8(local_light_shader_source(samples, batch_size, noise, false))
                        .expect("local-light variant");
                assert!(variant.starts_with(&format!(
                    "#define LOCAL_LIGHT_SAMPLE_COUNT {samples}\n#define LOCAL_LIGHT_BATCH_SIZE {batch_size}\n#define LOCAL_LIGHT_USE_NOISE {}\n#define LOCAL_LIGHT_USE_NATIVE_SHADOW 0\n",
                    u8::from(noise),
                )));
            }
            let shadowed = String::from_utf8(local_light_shader_source(samples, 1, noise, true))
                .expect("shadowed local-light variant");
            assert!(shadowed.starts_with(&format!(
                "#define LOCAL_LIGHT_SAMPLE_COUNT {samples}\n#define LOCAL_LIGHT_BATCH_SIZE 1\n#define LOCAL_LIGHT_USE_NOISE {}\n#define LOCAL_LIGHT_USE_NATIVE_SHADOW 1\n",
                u8::from(noise),
            )));
        }
    }

    #[test]
    fn batched_local_light_bytecode_stays_within_the_ps3_budget() {
        for (samples, noise) in [(4, false), (6, true), (10, true)] {
            let single = crate::shaders::compile_hlsl_source_target(
                "local-light-single-budget",
                &local_light_shader_source(samples, 1, noise, false),
                "ps_3_0",
            )
            .expect("single local-light shader");
            assert!(
                single.len() * 4 <= 12_288,
                "single shader grew to {} bytes",
                single.len() * 4,
            );
            for batch_size in 2..=4 {
                let batch = crate::shaders::compile_hlsl_source_target(
                    "local-light-batch-budget",
                    &local_light_shader_source(samples, batch_size, noise, false),
                    "ps_3_0",
                )
                .expect("batched local-light shader");
                assert!(
                    batch.len() * 4 <= 32_768,
                    "batch {batch_size} grew to {} bytes",
                    batch.len() * 4
                );
                assert!(
                    batch.len() <= single.len() * batch_size,
                    "batch {batch_size} grew from {} to {} bytes",
                    single.len() * 4,
                    batch.len() * 4,
                );
            }
        }
    }

    #[test]
    fn atmosphere_vendor_coverage_disable_magic_is_exact() {
        assert_eq!(super::AMD_ALPHA_TO_COVERAGE_OFF, 0x304D_3241);
    }

    #[test]
    fn view_to_world_rows_map_d3d_axes_to_game_rotation_columns() {
        let camera = CameraFrame {
            world_transform: CameraTransformFrame {
                rotation: [[1.0, 2.0, 3.0], [4.0, 5.0, 6.0], [7.0, 8.0, 9.0]],
                translation: [10.0, 20.0, 30.0],
                scale: 2.0,
                available: true,
            },
            ..CameraFrame::default()
        };

        assert_eq!(
            view_to_world_rows(camera),
            [
                [6.0, 4.0, 2.0, 10.0],
                [12.0, 10.0, 8.0, 20.0],
                [18.0, 16.0, 14.0, 30.0],
            ]
        );
    }
}

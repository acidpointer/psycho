//! World-only volumetric atmosphere foundation.

use libpsycho::os::windows::directx9::{
    D3DCULL_NONE, D3DFMT_A8R8G8B8, D3DFMT_A16B16G16R16F, D3DFMT_G16R16F, D3DFORMAT,
    D3DPOOL_MANAGED, D3DPT_TRIANGLESTRIP, D3DRS_ALPHABLENDENABLE, D3DRS_ALPHATESTENABLE,
    D3DRS_COLORWRITEENABLE, D3DRS_CULLMODE, D3DRS_MULTISAMPLEANTIALIAS, D3DRS_MULTISAMPLEMASK,
    D3DRS_SCISSORTESTENABLE, D3DRS_SRGBWRITEENABLE, D3DRS_STENCILENABLE, D3DRS_ZENABLE,
    D3DRS_ZWRITEENABLE, D3DSAMP_ADDRESSU, D3DSAMP_ADDRESSV, D3DSAMP_MAGFILTER, D3DSAMP_MINFILTER,
    D3DSAMP_MIPFILTER, D3DSAMP_SRGBTEXTURE, D3DSURFACE_DESC, D3DTA_TEXTURE, D3DTADDRESS_CLAMP,
    D3DTADDRESS_WRAP, D3DTEXF_LINEAR, D3DTEXF_NONE, D3DTEXF_POINT, D3DTOP_SELECTARG1,
    D3DTSS_ALPHAARG1, D3DTSS_ALPHAOP, D3DTSS_COLORARG1, D3DTSS_COLOROP, D3DVIEWPORT9, Device9Ref,
    Direct3DResult, PixelShader9, ScreenVertex, Surface9, Texture9, USAGE_RENDER_TARGET,
    direct3d_failure,
};

use crate::{
    backend::{AtmosphereFrame, DepthTexture},
    config::{AtmosphereQuality, VolumetricFogConfig, VolumetricLightingConfig},
    shaders::{self, ScreenShaderSource},
};

const COLOR_WRITE_ALL: u32 = 0x0F;
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
            height_density: finite(fog.height_density, 0.000002).clamp(0.0, 0.001),
            height_falloff: finite(fog.height_falloff, 0.0001).clamp(0.000001, 0.01),
            base_height: finite(fog.base_height, 0.0).clamp(-100_000.0, 100_000.0),
            max_distance: if fog.enabled {
                finite(fog.max_distance, 120_000.0).clamp(1_000.0, 250_000.0)
            } else {
                finite(lighting.max_distance, 120_000.0).clamp(1_000.0, 250_000.0)
            },
            scattering_albedo: finite(fog.scattering_albedo, 0.9).clamp(0.0, 1.0),
            noise_amount: finite(fog.noise_amount, 0.25).clamp(0.0, 1.0),
            noise_scale: finite(fog.noise_scale, 0.0005).clamp(0.000001, 0.05),
            noise_speed: finite(fog.noise_speed, 0.02).clamp(0.0, 1.0),
            temporal_stability: finite(fog.temporal_stability, 0.9).clamp(0.0, 0.98),
            debug_view: selected_debug_view(fog.debug_view, lighting.debug_view),
            quality: if fog.enabled {
                fog.quality
            } else {
                lighting.shaft_quality
            },
            lighting_intensity: finite(lighting.intensity, 1.0).clamp(0.0, 8.0),
            lighting_medium_density: finite(lighting.medium_density, 0.000002).clamp(0.0, 0.001),
            anisotropy: finite(lighting.anisotropy, 0.65).clamp(-0.8, 0.9),
            shaft_strength: finite(lighting.shaft_strength, 1.0).clamp(0.0, 1.0),
            sun_disk_boost: finite(lighting.sun_disk_boost, 1.0).clamp(0.0, 8.0),
            shaft_quality: lighting.shaft_quality,
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
        let height_density = option_component(fog_constants, 0, 1, 0.000002);
        let height_falloff = option_component(fog_constants, 0, 2, 0.0001);
        let base_height = option_component(fog_constants, 0, 3, 0.0);
        let max_distance = option_component(fog_constants, 1, 0, 120_000.0);
        let scattering_albedo = option_component(fog_constants, 1, 1, 0.9);
        let noise_amount = option_component(fog_constants, 1, 2, 0.25);
        let noise_scale = option_component(fog_constants, 1, 3, 0.0005);
        let noise_speed = option_component(fog_constants, 2, 0, 0.02);
        let temporal_stability = option_component(fog_constants, 2, 1, 0.9);
        let fog_debug = fog_constants
            .and_then(|constants| constants.get(2))
            .map_or(0, |value| finite_i32(value[3]));
        let lighting_intensity = option_component(lighting_constants, 0, 0, 1.0);
        let lighting_medium_density = option_component(lighting_constants, 0, 1, 0.000002);
        let lighting_max_distance = option_component(lighting_constants, 0, 2, 120_000.0);
        let anisotropy = option_component(lighting_constants, 0, 3, 0.65);
        let shaft_strength = option_component(lighting_constants, 1, 0, 1.0);
        let sun_disk_boost = option_component(lighting_constants, 1, 1, 1.0);
        let lighting_debug = lighting_constants
            .and_then(|constants| constants.get(1))
            .map_or(0, |value| finite_i32(value[3]));
        let fog_quality = fog_constants
            .and_then(|constants| constants.get(2))
            .map(|value| AtmosphereQuality::from_index(finite_i32(value[2])));
        let lighting_quality = lighting_constants
            .and_then(|constants| constants.get(1))
            .map(|value| AtmosphereQuality::from_index(finite_i32(value[2])));
        let quality = fog_quality.or(lighting_quality).unwrap_or_default();

        Self {
            fog_enabled,
            lighting_enabled,
            density: finite(density, 0.0).clamp(0.0, 0.001),
            height_density: finite(height_density, 0.000002).clamp(0.0, 0.001),
            height_falloff: finite(height_falloff, 0.0001).clamp(0.000001, 0.01),
            base_height: finite(base_height, 0.0).clamp(-100_000.0, 100_000.0),
            max_distance: if fog_enabled {
                finite(max_distance, 120_000.0).clamp(1_000.0, 250_000.0)
            } else {
                finite(lighting_max_distance, 120_000.0).clamp(1_000.0, 250_000.0)
            },
            scattering_albedo: finite(scattering_albedo, 0.9).clamp(0.0, 1.0),
            noise_amount: finite(noise_amount, 0.25).clamp(0.0, 1.0),
            noise_scale: finite(noise_scale, 0.0005).clamp(0.000001, 0.05),
            noise_speed: finite(noise_speed, 0.02).clamp(0.0, 1.0),
            temporal_stability: finite(temporal_stability, 0.9).clamp(0.0, 0.98),
            debug_view: selected_debug_view(fog_debug, lighting_debug),
            quality,
            lighting_intensity: finite(lighting_intensity, 1.0).clamp(0.0, 8.0),
            lighting_medium_density: finite(lighting_medium_density, 0.000002).clamp(0.0, 0.001),
            anisotropy: finite(anisotropy, 0.65).clamp(-0.8, 0.9),
            shaft_strength: finite(shaft_strength, 1.0).clamp(0.0, 1.0),
            sun_disk_boost: finite(sun_disk_boost, 1.0).clamp(0.0, 8.0),
            shaft_quality: lighting_quality.unwrap_or_default(),
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
        match self.quality {
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

    fn effective_uniform_density(self) -> f32 {
        if self.fog_enabled {
            self.density
        } else {
            self.lighting_medium_density
        }
    }

    fn effective_scattering_albedo(self) -> f32 {
        if self.fog_enabled {
            self.scattering_albedo
        } else {
            1.0
        }
    }
}

fn selected_debug_view(fog: i32, lighting: i32) -> i32 {
    let lighting = lighting.clamp(0, 5);
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

#[derive(Clone, Copy, Debug, Default)]
struct SunProjection {
    uv: [f32; 2],
    facing: f32,
    edge_fade: f32,
    on_screen: bool,
}

#[derive(Clone, Copy, Debug)]
struct DirectionalLight {
    world_direction: [f32; 3],
    linear_color: [f32; 3],
    linear_disk_delta: [f32; 3],
    daylight: f32,
    projection: SunProjection,
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
) -> SunProjection {
    let transform = camera.world_transform;
    if !camera.available || !transform.available || !world_direction.into_iter().all(f32::is_finite)
    {
        return SunProjection::default();
    }
    let direction_length = dot3(world_direction, world_direction).sqrt();
    if !direction_length.is_finite() || direction_length <= 0.000001 {
        return SunProjection::default();
    }
    let direction = world_direction.map(|value| value / direction_length);
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
    let view_x = dot3(direction, right);
    let view_y = dot3(direction, up);
    let facing = dot3(direction, forward);
    let frustum_width = camera.frustum_right - camera.frustum_left;
    let frustum_height = camera.frustum_top - camera.frustum_bottom;
    if !facing.is_finite()
        || facing <= 0.001
        || !frustum_width.is_finite()
        || !frustum_height.is_finite()
        || frustum_width <= f32::EPSILON
        || frustum_height <= f32::EPSILON
    {
        return SunProjection {
            facing: finite(facing, 0.0),
            ..SunProjection::default()
        };
    }

    let ndc_x =
        (2.0 * view_x / facing - (camera.frustum_right + camera.frustum_left)) / frustum_width;
    let ndc_y =
        (2.0 * view_y / facing - (camera.frustum_top + camera.frustum_bottom)) / frustum_height;
    let uv = [ndc_x.mul_add(0.5, 0.5), ndc_y.mul_add(-0.5, 0.5)];
    if !uv.into_iter().all(f32::is_finite) {
        return SunProjection::default();
    }
    let edge = uv[0].min(1.0 - uv[0]).min(uv[1].min(1.0 - uv[1]));
    let edge_fade = smooth01((edge / 0.035).clamp(0.0, 1.0));
    SunProjection {
        uv,
        facing,
        edge_fade,
        on_screen: edge >= 0.0,
    }
}

fn smooth01(value: f32) -> f32 {
    let value = finite(value, 0.0).clamp(0.0, 1.0);
    value * value * (3.0 - 2.0 * value)
}

fn dot3(a: [f32; 3], b: [f32; 3]) -> f32 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

pub(crate) struct AtmosphereEffect {
    depth_reduce_half_shader: PixelShader9,
    depth_reduce_quarter_shader: PixelShader9,
    shaft_pipeline: Option<ShaftPipeline>,
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
    composition_draws: u64,
    debug_draws: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AtmosphereDrawOutcome {
    Skipped,
    Composed,
    ComposedWithLighting,
    DebugDrawn,
    LightingDebugDrawn,
}

impl AtmosphereDrawOutcome {
    pub(crate) fn drew(self) -> bool {
        self != Self::Skipped
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
    ) -> Direct3DResult<AtmosphereDrawOutcome> {
        self.log_contract(
            desc,
            frame,
            world_color.is_some(),
            taa_enabled,
            taa_alpha_ready,
        );
        let integration_gate = fog_integration_gate(frame, settings);
        self.log_integration_gate(integration_gate, settings);
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

        if settings.debug_view == 0 {
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
            return Ok(if contributions.lighting_ready() {
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
                settings.effective_uniform_density(),
                fog_density,
                settings.height_falloff,
                settings.base_height,
            ],
            [
                settings.max_distance,
                settings.effective_scattering_albedo(),
                noise_amount,
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
        ],
    )?;
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
) -> FogIntegrationGate {
    if !settings.fog_enabled && !settings.lighting_enabled {
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
    if !frame.material_state.is_exterior {
        return FogIntegrationGate::Interior;
    }
    if !frame.underwater_contract_ready() {
        return FogIntegrationGate::UnderwaterUnknown;
    }
    if frame.underwater.underwater {
        return FogIntegrationGate::Underwater;
    }
    if !resolve_contributions(frame, settings).any() {
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
    if settings.debug_view != 0 {
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
    if frame.environment.fog_available
        && let Some(linear_rgb) = linearize_native_color(frame.environment.fog_color)
    {
        return Some(MediumColor { linear_rgb });
    }
    let sky = frame.sky?;
    if !frame.material_state.exterior_known || !frame.material_state.is_exterior || !sky.is_exterior
    {
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
    Some(DirectionalLight {
        world_direction: sky.sun_direction,
        linear_color,
        linear_disk_delta,
        daylight: sky.daylight.clamp(0.0, 1.0),
        projection: project_sun_from_captured_camera(frame.camera, sky.sun_direction),
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
        atmosphere_layer_blend, bounded_shaft_visibility, decode_extended_srgb,
        density_noise_pixels, directional_phase_response, directional_radiance,
        encode_extended_srgb, fog_composition_gate, fog_integration_gate, henyey_greenstein,
        layered_tap_weight, linearize_native_color, option_component,
        project_sun_from_captured_camera, resolve_contributions, resolve_medium_color,
        selected_debug_view, shaft_visibility_from_blocked_fraction,
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
        assert!((0.979..0.981).contains(&transmittance));
    }

    #[test]
    fn lighting_default_keeps_distant_extinction_bounded() {
        let mut config = EmbeddedEffectsConfig::default();
        config.volumetric_lighting.enabled = true;
        let settings =
            AtmosphereSettings::from_config(config.volumetric_fog, config.volumetric_lighting);
        let frame = valid_frame();

        assert_eq!(settings.lighting_medium_density, 0.000002);
        assert!((0.786..0.788).contains(&settings.estimated_horizontal_transmittance(frame)));
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
        config.volumetric_lighting.enabled = true;
        config.volumetric_lighting.intensity = 2.5;
        config.volumetric_lighting.medium_density = 0.00004;
        config.volumetric_lighting.max_distance = 88_000.0;
        config.volumetric_lighting.anisotropy = 0.4;
        config.volumetric_lighting.shaft_strength = 0.7;
        config.volumetric_lighting.sun_disk_boost = 3.0;
        config.volumetric_lighting.shaft_quality = AtmosphereQuality::Ultra;
        config.volumetric_lighting.debug_view = 5;
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
        assert_eq!(settings.lighting_debug_view(), 5);
        assert!(settings.requires_depth());
        assert!(settings.requires_world_color());

        let choices = source
            .options
            .iter()
            .find(|option| option.key == "debug_view")
            .and_then(|option| option.choices)
            .expect("lighting debug choices");
        assert_eq!(choices.len(), 6);
        assert_eq!(choices[1], "Shaft mask");
        assert_eq!(choices[5], "Combined acceptance");
    }

    #[test]
    fn lighting_debug_selection_has_explicit_precedence() {
        assert_eq!(selected_debug_view(0, 0), 0);
        assert_eq!(selected_debug_view(7, 0), 7);
        assert_eq!(selected_debug_view(7, 2), 10);
        assert_eq!(selected_debug_view(99, 99), 13);
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
    fn fog_and_directional_lighting_contributions_are_independent() {
        let frame = valid_frame();
        let fog_only = settings();
        let contributions = resolve_contributions(frame, fog_only);
        assert!(contributions.fog);
        assert!(!contributions.lighting_ready());
        assert_eq!(
            fog_integration_gate(frame, fog_only),
            FogIntegrationGate::Ready
        );

        let mut lighting_only = settings();
        lighting_only.fog_enabled = false;
        lighting_only.lighting_enabled = true;
        assert_eq!(
            fog_integration_gate(frame, lighting_only),
            FogIntegrationGate::NoReadyContribution
        );
        let mut sun_frame = frame;
        sun_frame.sky = Some(valid_sky([1.0, 0.0, 0.0]));
        let contributions = resolve_contributions(sun_frame, lighting_only);
        assert!(!contributions.fog);
        assert!(contributions.lighting_ready());
        assert_eq!(
            fog_integration_gate(sun_frame, lighting_only),
            FogIntegrationGate::Ready
        );
        assert_eq!(
            lighting_only.effective_uniform_density(),
            lighting_only.lighting_medium_density
        );
        assert_eq!(lighting_only.effective_scattering_albedo(), 1.0);

        let mut combined = settings();
        combined.lighting_enabled = true;
        combined.lighting_medium_density = 0.0009;
        assert_eq!(combined.effective_uniform_density(), combined.density);
        assert_eq!(
            combined.effective_scattering_albedo(),
            combined.scattering_albedo
        );
        let missing_sun = resolve_contributions(frame, combined);
        assert!(missing_sun.fog);
        assert!(!missing_sun.lighting_ready());
        assert_eq!(
            fog_integration_gate(frame, combined),
            FogIntegrationGate::Ready
        );
        let ready = resolve_contributions(sun_frame, combined);
        assert!(ready.fog && ready.lighting_ready());
    }

    #[test]
    fn draw_outcomes_report_whether_the_atmosphere_drew() {
        assert!(!AtmosphereDrawOutcome::Skipped.drew());
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
            fog_integration_gate(frame, settings),
            FogIntegrationGate::Ready
        );

        frame.underwater.frame_epoch = 6;
        assert_eq!(
            fog_integration_gate(frame, settings),
            FogIntegrationGate::UnderwaterUnknown
        );
        frame.underwater.frame_epoch = 7;
        frame.underwater.underwater = true;
        assert_eq!(
            fog_integration_gate(frame, settings),
            FogIntegrationGate::Underwater
        );
        frame.underwater.underwater = false;
        frame.material_state.is_exterior = false;
        assert_eq!(
            fog_integration_gate(frame, settings),
            FogIntegrationGate::Interior
        );
    }

    #[test]
    fn integration_gate_fails_closed_for_each_required_contract_group() {
        let mut settings = settings();
        let mut frame = valid_frame();

        settings.fog_enabled = false;
        assert_eq!(
            fog_integration_gate(frame, settings),
            FogIntegrationGate::Disabled
        );
        settings.fog_enabled = true;
        settings.density = 0.0;
        settings.height_density = 0.0;
        assert_eq!(
            fog_integration_gate(frame, settings),
            FogIntegrationGate::EmptyMedium
        );
        settings.height_density = 0.00002;

        frame.depth = DepthFrame::none();
        assert_eq!(
            fog_integration_gate(frame, settings),
            FogIntegrationGate::MissingDepthContract
        );
        frame = valid_frame();
        frame.camera.world_transform.available = false;
        assert_eq!(
            fog_integration_gate(frame, settings),
            FogIntegrationGate::MissingWorldTransform
        );
        frame = valid_frame();
        frame.material_state.exterior_known = false;
        assert_eq!(
            fog_integration_gate(frame, settings),
            FogIntegrationGate::ExteriorUnknown
        );
        frame = valid_frame();
        frame.environment.fog_available = false;
        assert_eq!(
            fog_integration_gate(frame, settings),
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
}

#[cfg(test)]
mod shader_compile_tests {
    use super::{
        COMPOSE_SHADER, DEBUG_SHADER, DEPTH_REDUCE_SHADER, INTEGRATE_SHADER, SHAFT_MASK_SHADER,
        SHAFT_RADIAL_SHADER, depth_reduce_shader_source, integration_shader_source,
        shaft_radial_shader_source, view_to_world_rows,
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
        assert!(integrate.contains("HenyeyGreenstein"));
        assert!(integrate.contains("HenyeyGreenstein(mu, LightingData.y) * FourPi"));
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

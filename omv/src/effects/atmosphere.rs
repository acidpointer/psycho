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
const DENSITY_NOISE_SIZE: u32 = 64;
const DENSITY_NOISE_SEED: u32 = 0xA7F4_31D9;

#[derive(Clone, Copy, Debug)]
pub(crate) struct AtmosphereSettings {
    fog_enabled: bool,
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
}

impl AtmosphereSettings {
    pub(crate) fn from_config(
        fog: VolumetricFogConfig,
        lighting: VolumetricLightingConfig,
    ) -> Self {
        Self {
            fog_enabled: fog.enabled,
            density: finite(fog.density, 0.0).clamp(0.0, 0.001),
            height_density: finite(fog.height_density, 0.000002).clamp(0.0, 0.001),
            height_falloff: finite(fog.height_falloff, 0.0001).clamp(0.000001, 0.01),
            base_height: finite(fog.base_height, 0.0).clamp(-100_000.0, 100_000.0),
            max_distance: finite(fog.max_distance, 120_000.0).clamp(1_000.0, 250_000.0),
            scattering_albedo: finite(fog.scattering_albedo, 0.9).clamp(0.0, 1.0),
            noise_amount: finite(fog.noise_amount, 0.25).clamp(0.0, 1.0),
            noise_scale: finite(fog.noise_scale, 0.0005).clamp(0.000001, 0.05),
            noise_speed: finite(fog.noise_speed, 0.02).clamp(0.0, 1.0),
            temporal_stability: finite(fog.temporal_stability, 0.9).clamp(0.0, 0.98),
            debug_view: fog.debug_view.max(lighting.debug_view).clamp(0, 8),
            quality: if fog.enabled {
                fog.quality
            } else {
                lighting.shaft_quality
            },
        }
    }

    pub(crate) fn from_sources(
        fog: Option<&ScreenShaderSource>,
        lighting: Option<&ScreenShaderSource>,
    ) -> Self {
        let fog_constants = fog.map(|source| source.option_constants.as_slice());
        let lighting_constants = lighting.map(|source| source.option_constants.as_slice());
        let fog_enabled = fog.is_some();
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
            density: finite(density, 0.0).clamp(0.0, 0.001),
            height_density: finite(height_density, 0.000002).clamp(0.0, 0.001),
            height_falloff: finite(height_falloff, 0.0001).clamp(0.000001, 0.01),
            base_height: finite(base_height, 0.0).clamp(-100_000.0, 100_000.0),
            max_distance: finite(max_distance, 120_000.0).clamp(1_000.0, 250_000.0),
            scattering_albedo: finite(scattering_albedo, 0.9).clamp(0.0, 1.0),
            noise_amount: finite(noise_amount, 0.25).clamp(0.0, 1.0),
            noise_scale: finite(noise_scale, 0.0005).clamp(0.000001, 0.05),
            noise_speed: finite(noise_speed, 0.02).clamp(0.0, 1.0),
            temporal_stability: finite(temporal_stability, 0.9).clamp(0.0, 0.98),
            debug_view: fog_debug.max(lighting_debug).clamp(0, 8),
            quality,
        }
    }

    pub(crate) fn requires_world_color(self) -> bool {
        self.requires_integration() || self.debug_view != 0
    }

    pub(crate) fn requires_depth(self) -> bool {
        self.requires_integration() || self.debug_view != 0
    }

    pub(crate) fn requires_integration(self) -> bool {
        self.fog_enabled && (self.density > 0.0 || self.height_density > 0.0)
    }

    pub(crate) fn estimated_horizontal_transmittance(self, frame: AtmosphereFrame) -> f32 {
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
    MissingMediumColor,
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
            Self::MissingMediumColor => "missing_medium_color",
            Self::Ready => "ready",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct MediumColor {
    linear_rgb: [f32; 3],
    source: f32,
}

pub(crate) struct AtmosphereEffect {
    depth_reduce_half_shader: PixelShader9,
    depth_reduce_quarter_shader: PixelShader9,
    integrate_shaders: [PixelShader9; 3],
    compose_shader: PixelShader9,
    debug_shader: PixelShader9,
    density_noise: Texture9,
    targets: Option<AtmosphereTargets>,
    failed_target_size: Option<(u32, u32, u32)>,
    last_contract: Option<u16>,
    last_fog_signature: Option<[i32; 6]>,
    contract_logs: u32,
    last_integration_gate: Option<FogIntegrationGate>,
    integration_gate_logs: u32,
    last_composition_gate: Option<FogCompositionGate>,
    composition_gate_logs: u32,
    integration_draws: u64,
    composition_draws: u64,
    debug_draws: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AtmosphereDrawOutcome {
    Skipped,
    Composed,
    DebugDrawn,
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
            targets: None,
            failed_target_size: None,
            last_contract: None,
            last_fog_signature: None,
            contract_logs: 0,
            last_integration_gate: None,
            integration_gate_logs: 0,
            last_composition_gate: None,
            composition_gate_logs: 0,
            integration_draws: 0,
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
        let integration_ready = if integration_gate == FogIntegrationGate::Ready {
            let Some(medium_color) = resolve_medium_color(frame) else {
                return Ok(AtmosphereDrawOutcome::Skipped);
            };
            draw_integration(
                device,
                &self.integrate_shaders[settings.shader_index()],
                targets,
                &self.density_noise,
                frame,
                settings,
                medium_color,
            )?;
            self.integration_draws = self.integration_draws.saturating_add(1);
            if self.integration_draws == 1 {
                log::info!(
                    "[ATMOSPHERE] Fog integration active: quality={:?}, scale={}, samples={}, target={}x{} A16B16G16R16F",
                    settings.quality,
                    settings.target_scale(),
                    settings.sample_count(),
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
                    "[ATMOSPHERE] Production fog composition active: quality={:?}, scale={}, target={}x{} format=0x{:08X}, transfer={}",
                    settings.quality,
                    settings.target_scale(),
                    desc.Width,
                    desc.Height,
                    desc.Format.0,
                    SOURCE_TRANSFER.label(),
                );
            }
            return Ok(AtmosphereDrawOutcome::Composed);
        }
        if settings.debug_view >= 6 && !integration_ready {
            return Ok(AtmosphereDrawOutcome::Skipped);
        }
        let Some(world_color) = world_color else {
            return Ok(AtmosphereDrawOutcome::Skipped);
        };
        if settings.debug_view == 8 {
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
            )?;
        }
        self.debug_draws = self.debug_draws.saturating_add(1);
        Ok(AtmosphereDrawOutcome::DebugDrawn)
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
                    "[ATMOSPHERE] Targets: full={}x{}, reduced={}x{}, scale={}, depth=G16R16F, integration=A16B16G16R16F",
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

#[allow(clippy::too_many_arguments)]
fn draw_integration(
    device: &Device9Ref<'_>,
    shader: &PixelShader9,
    targets: &AtmosphereTargets,
    density_noise: &Texture9,
    frame: AtmosphereFrame,
    settings: AtmosphereSettings,
    medium_color: MediumColor,
) -> Direct3DResult<()> {
    bind_target(
        device,
        &targets.integration.surface,
        targets.width,
        targets.height,
    )?;
    device.set_texture(0, &targets.depth.texture)?;
    device.set_texture(1, density_noise)?;
    set_sampler_filter(device, 0, D3DTEXF_POINT.0 as u32)?;
    set_sampler_filter(device, 1, D3DTEXF_LINEAR.0 as u32)?;
    device.set_sampler_state(1, D3DSAMP_ADDRESSU, D3DTADDRESS_WRAP.0 as u32)?;
    device.set_sampler_state(1, D3DSAMP_ADDRESSV, D3DTADDRESS_WRAP.0 as u32)?;
    let view_to_world = view_to_world_rows(frame.camera);
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
                settings.density,
                settings.height_density,
                settings.height_falloff,
                settings.base_height,
            ],
            [
                settings.max_distance,
                settings.scattering_albedo,
                settings.noise_amount,
                settings.noise_scale,
            ],
            [
                medium_color.linear_rgb[0],
                medium_color.linear_rgb[1],
                medium_color.linear_rgb[2],
                1.0,
            ],
            [1.0, 1.0, 0.0, medium_color.source],
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
    device.set_texture(3, &targets.integration.texture)?;
    for sampler in 0..=3 {
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
) -> Direct3DResult<()> {
    bind_target(device, world_target, desc.Width, desc.Height)?;
    device.set_texture(0, world_color)?;
    device.set_texture(1, &targets.depth.texture)?;
    device.set_texture(2, &targets.integration.texture)?;
    set_sampler_filter(device, 0, D3DTEXF_LINEAR.0 as u32)?;
    set_sampler_filter(device, 1, D3DTEXF_POINT.0 as u32)?;
    set_sampler_filter(device, 2, D3DTEXF_LINEAR.0 as u32)?;
    let view_to_world = view_to_world_rows(frame.camera);
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
    if !settings.fog_enabled {
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
    if resolve_medium_color(frame).is_none() {
        return FogIntegrationGate::MissingMediumColor;
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
        return Some(MediumColor {
            linear_rgb,
            source: 1.0,
        });
    }
    let sky = frame.sky?;
    if !frame.material_state.exterior_known || !frame.material_state.is_exterior || !sky.is_exterior
    {
        return None;
    }
    linearize_native_color(sky.horizon).map(|linear_rgb| MediumColor {
        linear_rgb,
        source: 2.0,
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
fn bilateral_tap_weight(full_distance: f32, nearest: f32, farthest: f32, scale: u32) -> f32 {
    let base_tolerance = (64.0 * scale.max(1) as f32).max(full_distance * 0.02);
    let span = (farthest - nearest).max(0.0);
    let mixed = (span / (base_tolerance * 4.0).max(1.0)).clamp(0.0, 1.0);
    let effective_tolerance =
        base_tolerance + (base_tolerance.mul_add(0.15, -base_tolerance)) * mixed;
    let depth_weight =
        (1.0 - (full_distance - nearest).abs() / effective_tolerance.max(1.0)).clamp(0.0, 1.0);
    depth_weight * depth_weight
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
    for sampler in 0..=3 {
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
    integration: EffectTarget,
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
            integration: EffectTarget::create(device, width, height, D3DFMT_A16B16G16R16F)?,
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
        AtmosphereSettings, FogCompositionGate, FogIntegrationGate, bilateral_tap_weight,
        decode_extended_srgb, density_noise_pixels, encode_extended_srgb, fog_composition_gate,
        fog_integration_gate, linearize_native_color, option_component, resolve_medium_color,
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
            FogIntegrationGate::MissingMediumColor
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
        assert_eq!(fog.source, 1.0);
        assert_eq!(
            fog.linear_rgb,
            linearize_native_color(frame.environment.fog_color).expect("finite fog")
        );

        frame.environment.fog_available = false;
        let horizon = resolve_medium_color(frame).expect("exterior horizon fallback");
        assert_eq!(horizon.source, 2.0);
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
    fn bilateral_key_rejects_background_inside_a_mixed_depth_interval() {
        assert_eq!(bilateral_tap_weight(100.0, 100.0, 100.0, 2), 1.0);
        assert!(bilateral_tap_weight(10_000.0, 100.0, 10_000.0, 2) <= f32::EPSILON);
        assert!(bilateral_tap_weight(5_050.0, 5_000.0, 5_100.0, 2) > 0.2);
        assert!(bilateral_tap_weight(7_000.0, 5_000.0, 5_100.0, 4) <= f32::EPSILON);
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
        COMPOSE_SHADER, DEBUG_SHADER, DEPTH_REDUCE_SHADER, depth_reduce_shader_source,
        integration_shader_source, view_to_world_rows,
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
        crate::shaders::assert_hlsl_compiles("atmosphere_compose.hlsl", COMPOSE_SHADER, "ps_3_0");
        crate::shaders::assert_hlsl_compiles("atmosphere_debug.hlsl", DEBUG_SHADER, "ps_3_0");
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

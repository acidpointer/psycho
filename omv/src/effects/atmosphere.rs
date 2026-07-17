//! World-only volumetric atmosphere foundation.

use libpsycho::os::windows::directx9::{
    D3DCULL_NONE, D3DFMT_G16R16F, D3DPT_TRIANGLESTRIP, D3DRS_ALPHABLENDENABLE,
    D3DRS_ALPHATESTENABLE, D3DRS_COLORWRITEENABLE, D3DRS_CULLMODE, D3DRS_SCISSORTESTENABLE,
    D3DRS_SRGBWRITEENABLE, D3DRS_ZENABLE, D3DRS_ZWRITEENABLE, D3DSAMP_ADDRESSU, D3DSAMP_ADDRESSV,
    D3DSAMP_MAGFILTER, D3DSAMP_MINFILTER, D3DSAMP_MIPFILTER, D3DSAMP_SRGBTEXTURE, D3DSURFACE_DESC,
    D3DTA_TEXTURE, D3DTADDRESS_CLAMP, D3DTEXF_LINEAR, D3DTEXF_NONE, D3DTEXF_POINT,
    D3DTOP_SELECTARG1, D3DTSS_ALPHAARG1, D3DTSS_ALPHAOP, D3DTSS_COLORARG1, D3DTSS_COLOROP,
    D3DVIEWPORT9, Device9Ref, Direct3DResult, PixelShader9, ScreenVertex, Surface9, Texture9,
    direct3d_failure,
};

use crate::{
    backend::{AtmosphereFrame, DepthTexture},
    shaders::{self, ScreenShaderSource},
};

const COLOR_WRITE_ALL: u32 = 0x0F;
const MAX_CONTRACT_LOGS: u32 = 32;
const DEPTH_REDUCE_SHADER: &[u8] =
    include_bytes!("../../shaders/embedded/atmosphere_depth_reduce.hlsl");
const DEBUG_SHADER: &[u8] = include_bytes!("../../shaders/embedded/atmosphere_debug.hlsl");

#[derive(Clone, Copy)]
pub(crate) struct AtmosphereSettings {
    pub(crate) max_distance: f32,
    debug_view: i32,
    target_scale: u32,
}

impl AtmosphereSettings {
    pub(crate) fn from_sources(
        fog: Option<&ScreenShaderSource>,
        lighting: Option<&ScreenShaderSource>,
    ) -> Self {
        let fog_constants = fog.map(|source| source.option_constants.as_slice());
        let lighting_constants = lighting.map(|source| source.option_constants.as_slice());
        let max_distance = fog_constants
            .and_then(|constants| constants.get(1))
            .map_or(120_000.0, |value| value[0]);
        let fog_debug = fog_constants
            .and_then(|constants| constants.get(2))
            .map_or(0, |value| finite_i32(value[3]));
        let lighting_debug = lighting_constants
            .and_then(|constants| constants.get(1))
            .map_or(0, |value| finite_i32(value[3]));
        let fog_quality = fog_constants
            .and_then(|constants| constants.get(2))
            .map(|value| finite_i32(value[2]));
        let lighting_quality = lighting_constants
            .and_then(|constants| constants.get(1))
            .map(|value| finite_i32(value[2]));
        let quality = fog_quality
            .into_iter()
            .chain(lighting_quality)
            .max()
            .unwrap_or(1)
            .clamp(0, 2);

        Self {
            max_distance: finite(max_distance, 120_000.0).clamp(1_000.0, 250_000.0),
            debug_view: fog_debug.max(lighting_debug).clamp(0, 2),
            target_scale: if quality == 0 { 4 } else { 2 },
        }
    }

    pub(crate) fn requires_world_color(self) -> bool {
        self.debug_view != 0
    }
}

pub(crate) struct AtmosphereEffect {
    depth_reduce_half_shader: PixelShader9,
    depth_reduce_quarter_shader: PixelShader9,
    debug_shader: PixelShader9,
    targets: Option<AtmosphereTargets>,
    failed_target_size: Option<(u32, u32, u32)>,
    last_contract: Option<u16>,
    last_fog_signature: Option<[i32; 6]>,
    contract_logs: u32,
}

impl AtmosphereEffect {
    pub(crate) fn create(device: &Device9Ref<'_>) -> Direct3DResult<Self> {
        device
            .direct3d()?
            .check_default_render_target_texture_support(D3DFMT_G16R16F)?;
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
            debug_shader: compile_shader(device, "atmosphere_debug.hlsl", DEBUG_SHADER)?,
            targets: None,
            failed_target_size: None,
            last_contract: None,
            last_fog_signature: None,
            contract_logs: 0,
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
    ) -> Direct3DResult<()> {
        self.log_contract(desc, frame, world_color.is_some());
        let Some(depth) = frame.depth.texture else {
            return Ok(());
        };
        if !frame.camera.available
            || frame.depth.world_projection.reversed_depth.is_none()
            || !frame.distance_bound.is_finite()
            || frame.distance_bound <= frame.camera.near_z
        {
            return Ok(());
        }

        self.ensure_targets(device, desc, settings.target_scale)?;
        let Some(targets) = self.targets.as_ref() else {
            return Ok(());
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
        if settings.debug_view == 0 {
            return Ok(());
        }
        let Some(world_color) = world_color else {
            return Ok(());
        };

        draw_debug(
            device,
            &self.debug_shader,
            world_target,
            desc,
            targets,
            world_color,
            frame.distance_bound,
            settings.debug_view,
        )
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
                    "[ATMOSPHERE] Depth target: full={}x{}, reduced={}x{}, scale={}, format=G16R16F",
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

    fn log_contract(&mut self, desc: &D3DSURFACE_DESC, frame: AtmosphereFrame, world_color: bool) {
        let contract = (frame.depth.texture.is_some() as u16)
            | ((frame.camera.available as u16) << 1)
            | ((frame.depth.world_projection.reversed_depth.is_some() as u16) << 2)
            | ((frame.environment.fog_available as u16) << 3)
            | ((frame.sky.is_some() as u16) << 4)
            | ((frame.sun.available as u16) << 5)
            | ((frame.material_state.exterior_known as u16) << 6)
            | ((frame.material_state.is_exterior as u16) << 7)
            | ((world_color as u16) << 8);
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
            "[ATMOSPHERE] Contract: target={}x{} format=0x{:08X}, epoch={}, depth={}, camera={}, reversed={:?}, world_color={}, fog={} rgb=({:.4},{:.4},{:.4}) range=({:.2},{:.2}) power={:.4}, sky={}, sun={}, exterior={:?}, distance_bound={:.2}",
            desc.Width,
            desc.Height,
            desc.Format.0,
            frame.frame_epoch,
            frame.depth.texture.is_some(),
            frame.camera.available,
            frame.depth.world_projection.reversed_depth,
            world_color,
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
            frame.distance_bound,
        );
    }
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
fn draw_debug(
    device: &Device9Ref<'_>,
    shader: &PixelShader9,
    world_target: &Surface9,
    desc: &D3DSURFACE_DESC,
    targets: &AtmosphereTargets,
    world_color: &Texture9,
    distance_bound: f32,
    debug_view: i32,
) -> Direct3DResult<()> {
    bind_target(device, world_target, desc.Width, desc.Height)?;
    device.set_texture(0, world_color)?;
    device.set_texture(1, &targets.depth.texture)?;
    set_sampler_filter(device, 0, D3DTEXF_LINEAR.0 as u32)?;
    set_sampler_filter(device, 1, D3DTEXF_POINT.0 as u32)?;
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
            [distance_bound, debug_view as f32, 0.0, 0.0],
        ],
    )?;
    device.set_pixel_shader(shader)?;
    draw_quad(device, desc.Width, desc.Height)
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

fn bind_pipeline_state(device: &Device9Ref<'_>) -> Direct3DResult<()> {
    device.clear_vertex_shader()?;
    device.set_fvf(ScreenVertex::FVF)?;
    device.set_render_state(D3DRS_CULLMODE, D3DCULL_NONE.0 as u32)?;
    device.set_render_state(D3DRS_ALPHABLENDENABLE, 0)?;
    device.set_render_state(D3DRS_ALPHATESTENABLE, 0)?;
    device.set_render_state(D3DRS_ZENABLE, 0)?;
    device.set_render_state(D3DRS_ZWRITEENABLE, 0)?;
    device.set_render_state(D3DRS_SCISSORTESTENABLE, 0)?;
    device.set_render_state(D3DRS_SRGBWRITEENABLE, 0)?;
    device.set_render_state(D3DRS_COLORWRITEENABLE, COLOR_WRITE_ALL)?;
    for sampler in 0..=1 {
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
            depth: EffectTarget::create(device, width, height)?,
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
    fn create(device: &Device9Ref<'_>, width: u32, height: u32) -> Direct3DResult<Self> {
        let texture = device.create_render_target_texture(width, height, D3DFMT_G16R16F)?;
        let surface = texture.surface_level(0)?;
        Ok(Self { texture, surface })
    }
}

#[cfg(test)]
mod shader_compile_tests {
    use super::{DEBUG_SHADER, DEPTH_REDUCE_SHADER, depth_reduce_shader_source};

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
        crate::shaders::assert_hlsl_compiles("atmosphere_debug.hlsl", DEBUG_SHADER, "ps_3_0");
    }
}

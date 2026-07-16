//! Engine-side sunshafts pipeline.

use libpsycho::os::windows::directx9::{
    D3DCULL_NONE, D3DFORMAT, D3DPT_TRIANGLESTRIP, D3DRS_ALPHABLENDENABLE, D3DRS_ALPHATESTENABLE,
    D3DRS_COLORWRITEENABLE, D3DRS_CULLMODE, D3DRS_ZENABLE, D3DRS_ZWRITEENABLE, D3DSAMP_ADDRESSU,
    D3DSAMP_ADDRESSV, D3DSAMP_MAGFILTER, D3DSAMP_MINFILTER, D3DSAMP_MIPFILTER, D3DSURFACE_DESC,
    D3DTA_TEXTURE, D3DTADDRESS_CLAMP, D3DTEXF_LINEAR, D3DTEXF_NONE, D3DTEXF_POINT,
    D3DTOP_SELECTARG1, D3DTSS_ALPHAARG1, D3DTSS_ALPHAOP, D3DTSS_COLORARG1, D3DTSS_COLOROP,
    D3DVIEWPORT9, Device9Ref, Direct3DResult, PixelShader9, ScreenVertex, Surface9, Texture9,
    direct3d_failure,
};

use crate::{
    backend::{DepthTexture, FrameInputs},
    shaders::{self, ScreenShaderSource},
};

const COLOR_WRITE_ALL: u32 = 0x0F;
const EFFECT_CONSTANT_REGISTER: u32 = 9;
const MASK_SCALE: u32 = 2;

const MASK_SHADER: &[u8] = include_bytes!("../../shaders/embedded/sunshafts_mask.hlsl");
const RADIAL_SHADER: &[u8] = include_bytes!("../../shaders/embedded/sunshafts_radial.hlsl");
const BLUR_SHADER: &[u8] = include_bytes!("../../shaders/embedded/sunshafts_blur.hlsl");
const COMPOSE_SHADER: &[u8] = include_bytes!("../../shaders/embedded/sunshafts_compose.hlsl");

#[cfg(test)]
mod shader_compile_tests {
    use super::{BLUR_SHADER, COMPOSE_SHADER, MASK_SHADER, RADIAL_SHADER};

    #[test]
    fn embedded_sunshaft_shaders_compile() {
        for (name, source) in [
            ("sunshafts_mask.hlsl", MASK_SHADER),
            ("sunshafts_radial.hlsl", RADIAL_SHADER),
            ("sunshafts_blur.hlsl", BLUR_SHADER),
            ("sunshafts_compose.hlsl", COMPOSE_SHADER),
        ] {
            crate::shaders::assert_hlsl_compiles(name, source, "ps_3_0");
        }
    }
}

pub(crate) struct SunshaftsEffect {
    mask_shader: PixelShader9,
    radial_shader: PixelShader9,
    blur_shader: PixelShader9,
    compose_shader: PixelShader9,
    targets: Option<SunshaftTargets>,
}

impl SunshaftsEffect {
    pub(crate) fn create(device: &Device9Ref<'_>) -> Direct3DResult<Self> {
        Ok(Self {
            mask_shader: compile_shader(device, "sunshafts_mask.hlsl", MASK_SHADER)?,
            radial_shader: compile_shader(device, "sunshafts_radial.hlsl", RADIAL_SHADER)?,
            blur_shader: compile_shader(device, "sunshafts_blur.hlsl", BLUR_SHADER)?,
            compose_shader: compile_shader(device, "sunshafts_compose.hlsl", COMPOSE_SHADER)?,
            targets: None,
        })
    }

    pub(crate) fn draw(
        &mut self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &FrameInputs,
        source: &ScreenShaderSource,
        scene_color: &Texture9,
        frame_index: u32,
    ) -> Direct3DResult<()> {
        if frame_inputs.sun.available_f32() <= 0.5
            || frame_inputs.depth.texture.is_none()
            || (frame_inputs.material_state.exterior_known
                && !frame_inputs.material_state.is_exterior)
        {
            return Ok(());
        }

        self.ensure_targets(device, desc)?;
        let Some(targets) = self.targets.as_ref() else {
            return Ok(());
        };

        bind_pipeline_state(device)?;
        bind_depth_inputs(
            device,
            &frame_inputs.depth.texture,
            &frame_inputs.depth.first_person_texture,
        )?;

        self.draw_mask(
            device,
            targets,
            desc,
            frame_inputs,
            source,
            scene_color,
            frame_index,
        )?;
        self.draw_radial(device, targets, frame_inputs, source, frame_index)?;
        self.draw_blur(
            device,
            targets,
            frame_inputs,
            source,
            frame_index,
            [targets.inv_width, 0.0],
        )?;
        self.draw_blur(
            device,
            targets,
            frame_inputs,
            source,
            frame_index,
            [0.0, targets.inv_height],
        )?;
        self.draw_compose(
            device,
            backbuffer,
            desc,
            targets,
            frame_inputs,
            source,
            scene_color,
            frame_index,
        )
    }

    fn ensure_targets(
        &mut self,
        device: &Device9Ref<'_>,
        desc: &D3DSURFACE_DESC,
    ) -> Direct3DResult<()> {
        let width = (desc.Width / MASK_SCALE).max(1);
        let height = (desc.Height / MASK_SCALE).max(1);
        let format = desc.Format;

        let needs_targets = self
            .targets
            .as_ref()
            .is_none_or(|targets| !targets.matches(width, height, format));
        if needs_targets {
            self.targets = Some(SunshaftTargets::create(device, width, height, format)?);
            log::info!("[SUNSHAFTS] Intermediate targets: {}x{}", width, height);
        }

        Ok(())
    }

    fn draw_mask(
        &self,
        device: &Device9Ref<'_>,
        targets: &SunshaftTargets,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &FrameInputs,
        source: &ScreenShaderSource,
        scene_color: &Texture9,
        frame_index: u32,
    ) -> Direct3DResult<()> {
        bind_target(device, &targets.mask.surface, targets.width, targets.height)?;
        device.set_texture(0, scene_color)?;
        bind_common_constants(device, desc, frame_inputs, source, frame_index, 0.0)?;
        device.set_pixel_shader(&self.mask_shader)?;
        draw_quad(device, targets.width, targets.height)
    }

    fn draw_radial(
        &self,
        device: &Device9Ref<'_>,
        targets: &SunshaftTargets,
        frame_inputs: &FrameInputs,
        source: &ScreenShaderSource,
        frame_index: u32,
    ) -> Direct3DResult<()> {
        bind_target(
            device,
            &targets.radial.surface,
            targets.width,
            targets.height,
        )?;
        device.set_texture(0, &targets.mask.texture)?;
        bind_lowres_constants(device, targets, frame_inputs, source, frame_index, 1.0)?;
        device.set_pixel_shader(&self.radial_shader)?;
        draw_quad(device, targets.width, targets.height)
    }

    fn draw_blur(
        &self,
        device: &Device9Ref<'_>,
        targets: &SunshaftTargets,
        frame_inputs: &FrameInputs,
        source: &ScreenShaderSource,
        frame_index: u32,
        direction: [f32; 2],
    ) -> Direct3DResult<()> {
        let (input, output) = if direction[0] != 0.0 {
            (&targets.radial.texture, &targets.blur.surface)
        } else {
            (&targets.blur.texture, &targets.radial.surface)
        };

        bind_target(device, output, targets.width, targets.height)?;
        device.set_texture(0, input)?;
        bind_lowres_constants(device, targets, frame_inputs, source, frame_index, 2.0)?;
        device.set_pixel_shader_constant_f(
            EFFECT_CONSTANT_REGISTER,
            &[[direction[0], direction[1], 0.0, 0.0]],
        )?;
        device.set_pixel_shader(&self.blur_shader)?;
        draw_quad(device, targets.width, targets.height)
    }

    fn draw_compose(
        &self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        targets: &SunshaftTargets,
        frame_inputs: &FrameInputs,
        source: &ScreenShaderSource,
        scene_color: &Texture9,
        frame_index: u32,
    ) -> Direct3DResult<()> {
        bind_target(device, backbuffer, desc.Width, desc.Height)?;
        device.set_texture(0, scene_color)?;
        bind_depth_inputs(
            device,
            &frame_inputs.depth.texture,
            &frame_inputs.depth.first_person_texture,
        )?;
        device.set_texture(4, &targets.radial.texture)?;
        bind_common_constants(device, desc, frame_inputs, source, frame_index, 3.0)?;
        device.set_pixel_shader_constant_f(
            EFFECT_CONSTANT_REGISTER,
            &[[
                targets.inv_width,
                targets.inv_height,
                targets.width as f32,
                targets.height as f32,
            ]],
        )?;
        device.set_pixel_shader(&self.compose_shader)?;
        draw_quad(device, desc.Width, desc.Height)
    }
}

fn compile_shader(
    device: &Device9Ref<'_>,
    source_name: &str,
    source: &[u8],
) -> Direct3DResult<PixelShader9> {
    let bytecode = match shaders::compile_hlsl_source(source_name, source) {
        Ok(bytecode) => bytecode,
        Err(err) => {
            log::warn!("[SUNSHAFTS] Failed to compile {source_name}: {err:#}");
            return Err(direct3d_failure());
        }
    };

    device.create_pixel_shader(&bytecode)
}

fn bind_pipeline_state(device: &Device9Ref<'_>) -> Direct3DResult<()> {
    device.clear_vertex_shader()?;
    device.set_fvf(ScreenVertex::FVF)?;
    device.set_render_state(D3DRS_CULLMODE, D3DCULL_NONE.0 as u32)?;
    device.set_render_state(D3DRS_ALPHABLENDENABLE, 0)?;
    device.set_render_state(D3DRS_ALPHATESTENABLE, 0)?;
    device.set_render_state(D3DRS_ZENABLE, 0)?;
    device.set_render_state(D3DRS_ZWRITEENABLE, 0)?;
    device.set_render_state(D3DRS_COLORWRITEENABLE, COLOR_WRITE_ALL)?;
    for sampler in [0, 1, 2, 3, 4] {
        device.set_sampler_state(sampler, D3DSAMP_ADDRESSU, D3DTADDRESS_CLAMP.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_ADDRESSV, D3DTADDRESS_CLAMP.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_MINFILTER, D3DTEXF_LINEAR.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_MAGFILTER, D3DTEXF_LINEAR.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_MIPFILTER, D3DTEXF_NONE.0 as u32)?;
    }
    for sampler in [1, 2] {
        device.set_sampler_state(sampler, D3DSAMP_MINFILTER, D3DTEXF_POINT.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_MAGFILTER, D3DTEXF_POINT.0 as u32)?;
    }
    device.set_texture_stage_state(0, D3DTSS_COLOROP, D3DTOP_SELECTARG1.0 as u32)?;
    device.set_texture_stage_state(0, D3DTSS_COLORARG1, D3DTA_TEXTURE)?;
    device.set_texture_stage_state(0, D3DTSS_ALPHAOP, D3DTOP_SELECTARG1.0 as u32)?;
    device.set_texture_stage_state(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE)?;
    Ok(())
}

fn bind_target(
    device: &Device9Ref<'_>,
    surface: &Surface9,
    width: u32,
    height: u32,
) -> Direct3DResult<()> {
    let viewport = D3DVIEWPORT9 {
        X: 0,
        Y: 0,
        Width: width,
        Height: height,
        MinZ: 0.0,
        MaxZ: 1.0,
    };

    device.clear_texture(0)?;
    device.clear_texture(4)?;
    device.set_render_target(0, surface)?;
    device.set_viewport(&viewport)
}

fn bind_depth_inputs(
    device: &Device9Ref<'_>,
    world_depth: &Option<DepthTexture>,
    first_person_depth: &Option<DepthTexture>,
) -> Direct3DResult<()> {
    if let Some(depth) = world_depth {
        unsafe {
            device.set_raw_base_texture(1, depth.as_ptr())?;
        }
    } else {
        device.clear_texture(1)?;
    }

    if let Some(depth) = first_person_depth {
        unsafe {
            device.set_raw_base_texture(2, depth.as_ptr())?;
        }
    } else {
        device.clear_texture(2)?;
    }

    Ok(())
}

fn bind_common_constants(
    device: &Device9Ref<'_>,
    desc: &D3DSURFACE_DESC,
    frame_inputs: &FrameInputs,
    source: &ScreenShaderSource,
    frame_index: u32,
    pass_index: f32,
) -> Direct3DResult<()> {
    device.set_pixel_shader_constant_f(
        0,
        &[
            [
                desc.Width as f32,
                desc.Height as f32,
                1.0 / desc.Width as f32,
                1.0 / desc.Height as f32,
            ],
            [
                frame_index as f32,
                pass_index,
                4.0,
                frame_inputs.depth.is_available() as u8 as f32,
            ],
            [
                frame_inputs.camera.near_z,
                frame_inputs.camera.far_z,
                frame_inputs.camera.aspect_ratio,
                frame_inputs.depth.provider_id(),
            ],
        ],
    )?;
    bind_effect_constants(device, frame_inputs, source)
}

fn bind_lowres_constants(
    device: &Device9Ref<'_>,
    targets: &SunshaftTargets,
    frame_inputs: &FrameInputs,
    source: &ScreenShaderSource,
    frame_index: u32,
    pass_index: f32,
) -> Direct3DResult<()> {
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
                frame_index as f32,
                pass_index,
                4.0,
                frame_inputs.depth.is_available() as u8 as f32,
            ],
            [
                frame_inputs.camera.near_z,
                frame_inputs.camera.far_z,
                frame_inputs.camera.aspect_ratio,
                frame_inputs.depth.provider_id(),
            ],
        ],
    )?;
    bind_effect_constants(device, frame_inputs, source)
}

fn bind_effect_constants(
    device: &Device9Ref<'_>,
    frame_inputs: &FrameInputs,
    source: &ScreenShaderSource,
) -> Direct3DResult<()> {
    if !source.option_constants.is_empty() {
        device.set_pixel_shader_constant_f(3, &source.option_constants)?;
    }
    device.set_pixel_shader_constant_f(
        6,
        &[[
            frame_inputs.environment.fog_start,
            frame_inputs.environment.fog_end,
            frame_inputs.environment.fog_power,
            frame_inputs.environment.fog_available_f32(),
        ]],
    )?;
    device.set_pixel_shader_constant_f(
        8,
        &[[
            frame_inputs.sun.screen_x,
            frame_inputs.sun.screen_y,
            frame_inputs.sun.available_f32(),
            frame_inputs.sun.daylight,
        ]],
    )?;
    bind_depth_contract_constants(device, frame_inputs)
}

fn bind_depth_contract_constants(
    device: &Device9Ref<'_>,
    frame_inputs: &FrameInputs,
) -> Direct3DResult<()> {
    let world = frame_inputs.depth.world_projection;
    let first_person = frame_inputs.depth.first_person_projection;
    device.set_pixel_shader_constant_f(
        11,
        &[
            [
                world.reversed_depth_f32(),
                first_person.reversed_depth_f32(),
                frame_inputs.camera.available_f32(),
                first_person.camera.available_f32(),
            ],
            [
                frame_inputs.camera.frustum_left,
                frame_inputs.camera.frustum_right,
                frame_inputs.camera.frustum_bottom,
                frame_inputs.camera.frustum_top,
            ],
            [
                first_person.camera.near_z,
                first_person.camera.far_z,
                first_person.camera.aspect_ratio,
                0.0,
            ],
            [
                first_person.camera.frustum_left,
                first_person.camera.frustum_right,
                first_person.camera.frustum_bottom,
                first_person.camera.frustum_top,
            ],
        ],
    )
}

fn draw_quad(device: &Device9Ref<'_>, width: u32, height: u32) -> Direct3DResult<()> {
    let quad = fullscreen_quad(width, height);
    unsafe { device.draw_primitive_up(D3DPT_TRIANGLESTRIP, 2, &quad) }
}

fn fullscreen_quad(width: u32, height: u32) -> [ScreenVertex; 4] {
    let width = width as f32;
    let height = height as f32;
    [
        ScreenVertex::new(-0.5, -0.5, 0.0, 0.0),
        ScreenVertex::new(width - 0.5, -0.5, 1.0, 0.0),
        ScreenVertex::new(-0.5, height - 0.5, 0.0, 1.0),
        ScreenVertex::new(width - 0.5, height - 0.5, 1.0, 1.0),
    ]
}

struct SunshaftTargets {
    width: u32,
    height: u32,
    inv_width: f32,
    inv_height: f32,
    format: D3DFORMAT,
    mask: EffectTarget,
    radial: EffectTarget,
    blur: EffectTarget,
}

impl SunshaftTargets {
    fn create(
        device: &Device9Ref<'_>,
        width: u32,
        height: u32,
        format: D3DFORMAT,
    ) -> Direct3DResult<Self> {
        Ok(Self {
            width,
            height,
            inv_width: 1.0 / width as f32,
            inv_height: 1.0 / height as f32,
            format,
            mask: EffectTarget::create(device, width, height, format)?,
            radial: EffectTarget::create(device, width, height, format)?,
            blur: EffectTarget::create(device, width, height, format)?,
        })
    }

    fn matches(&self, width: u32, height: u32, format: D3DFORMAT) -> bool {
        self.width == width && self.height == height && self.format == format
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

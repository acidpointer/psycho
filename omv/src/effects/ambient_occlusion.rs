//! Engine-side ambient occlusion pipeline.

use libpsycho::os::windows::directx9::{
    D3DCULL_NONE, D3DFMT_G16R16F, D3DPT_TRIANGLESTRIP, D3DRS_ALPHABLENDENABLE,
    D3DRS_COLORWRITEENABLE, D3DRS_CULLMODE, D3DRS_ZENABLE, D3DRS_ZWRITEENABLE, D3DSAMP_ADDRESSU,
    D3DSAMP_ADDRESSV, D3DSAMP_MAGFILTER, D3DSAMP_MINFILTER, D3DSAMP_MIPFILTER, D3DTA_TEXTURE,
    D3DTADDRESS_CLAMP, D3DTEXF_LINEAR, D3DTEXF_NONE, D3DTEXF_POINT, D3DTOP_SELECTARG1,
    D3DTSS_ALPHAARG1, D3DTSS_ALPHAOP, D3DTSS_COLORARG1, D3DTSS_COLOROP, Device9Ref, Direct3DResult,
    PixelShader9, ScreenVertex, Surface9, Texture9,
};
use windows::{
    Win32::Graphics::Direct3D9::{D3DFORMAT, D3DSURFACE_DESC, D3DVIEWPORT9},
    core::Error as WindowsError,
};

use crate::{
    backend::{DepthTexture, FrameInputs},
    shaders::{self, ScreenShaderSource},
};

const COLOR_WRITE_ALL: u32 = 0x0F;
const CONTACT_OPTION_REGISTER: u32 = 7;
const EFFECT_CONSTANT_REGISTER: u32 = 10;
const AO_SCALE: u32 = 2;

const EXTRACT_SHADER: &[u8] =
    include_bytes!("../../shaders/embedded/ambient_occlusion_extract.hlsl");
const BLUR_SHADER: &[u8] = include_bytes!("../../shaders/embedded/ambient_occlusion_blur.hlsl");
const COMPOSE_SHADER: &[u8] =
    include_bytes!("../../shaders/embedded/ambient_occlusion_compose.hlsl");

pub(crate) struct AmbientOcclusionEffect {
    extract_shader: PixelShader9,
    blur_shader: PixelShader9,
    compose_shader: PixelShader9,
    targets: Option<AmbientOcclusionTargets>,
}

impl AmbientOcclusionEffect {
    pub(crate) fn create(device: &Device9Ref<'_>) -> Direct3DResult<Self> {
        Ok(Self {
            extract_shader: compile_shader(
                device,
                "ambient_occlusion_extract.hlsl",
                EXTRACT_SHADER,
            )?,
            blur_shader: compile_shader(device, "ambient_occlusion_blur.hlsl", BLUR_SHADER)?,
            compose_shader: compile_shader(
                device,
                "ambient_occlusion_compose.hlsl",
                COMPOSE_SHADER,
            )?,
            targets: None,
        })
    }

    pub(crate) fn draw(
        &mut self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &FrameInputs,
        fast_source: Option<&ScreenShaderSource>,
        contact_source: Option<&ScreenShaderSource>,
        scene_color: &Texture9,
        frame_index: u32,
    ) -> Direct3DResult<()> {
        if frame_inputs.depth.texture.is_none() {
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

        self.draw_extract(
            device,
            targets,
            desc,
            frame_inputs,
            fast_source,
            contact_source,
            frame_index,
        )?;
        self.draw_blur(
            device,
            targets,
            desc,
            frame_inputs,
            fast_source,
            contact_source,
            frame_index,
            [targets.inv_width, 0.0],
        )?;
        self.draw_blur(
            device,
            targets,
            desc,
            frame_inputs,
            fast_source,
            contact_source,
            frame_index,
            [0.0, targets.inv_height],
        )?;
        self.draw_compose(
            device,
            backbuffer,
            desc,
            targets,
            frame_inputs,
            fast_source,
            contact_source,
            scene_color,
            frame_index,
        )
    }

    fn ensure_targets(
        &mut self,
        device: &Device9Ref<'_>,
        desc: &D3DSURFACE_DESC,
    ) -> Direct3DResult<()> {
        let width = (desc.Width / AO_SCALE).max(1);
        let height = (desc.Height / AO_SCALE).max(1);
        let format = desc.Format;

        let needs_targets = self
            .targets
            .as_ref()
            .is_none_or(|targets| !targets.matches(width, height));
        if needs_targets {
            self.targets = Some(AmbientOcclusionTargets::create(
                device, width, height, format,
            )?);
            log::info!("[AO] Intermediate targets: {}x{}", width, height);
        }

        Ok(())
    }

    fn draw_extract(
        &self,
        device: &Device9Ref<'_>,
        targets: &AmbientOcclusionTargets,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &FrameInputs,
        fast_source: Option<&ScreenShaderSource>,
        contact_source: Option<&ScreenShaderSource>,
        frame_index: u32,
    ) -> Direct3DResult<()> {
        bind_target(
            device,
            &targets.occlusion.surface,
            targets.width,
            targets.height,
        )?;
        bind_fullres_constants(
            device,
            desc,
            frame_inputs,
            fast_source,
            contact_source,
            frame_index,
            0.0,
        )?;
        device.set_pixel_shader(&self.extract_shader)?;
        draw_quad(device, targets.width, targets.height)
    }

    fn draw_blur(
        &self,
        device: &Device9Ref<'_>,
        targets: &AmbientOcclusionTargets,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &FrameInputs,
        fast_source: Option<&ScreenShaderSource>,
        contact_source: Option<&ScreenShaderSource>,
        frame_index: u32,
        direction: [f32; 2],
    ) -> Direct3DResult<()> {
        let (input, output) = if direction[0] != 0.0 {
            (&targets.occlusion.texture, &targets.blur.surface)
        } else {
            (&targets.blur.texture, &targets.occlusion.surface)
        };

        bind_target(device, output, targets.width, targets.height)?;
        device.set_texture(0, input)?;
        bind_fullres_constants(
            device,
            desc,
            frame_inputs,
            fast_source,
            contact_source,
            frame_index,
            1.0,
        )?;
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
        targets: &AmbientOcclusionTargets,
        frame_inputs: &FrameInputs,
        fast_source: Option<&ScreenShaderSource>,
        contact_source: Option<&ScreenShaderSource>,
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
        device.set_texture(4, &targets.occlusion.texture)?;
        bind_fullres_constants(
            device,
            desc,
            frame_inputs,
            fast_source,
            contact_source,
            frame_index,
            2.0,
        )?;
        device.set_pixel_shader_constant_f(
            EFFECT_CONSTANT_REGISTER,
            &[[targets.inv_width, targets.inv_height, AO_SCALE as f32, 0.0]],
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
            log::warn!("[AO] Failed to compile {source_name}: {err:#}");
            return Err(WindowsError::from_hresult(
                windows::Win32::Foundation::E_FAIL,
            ));
        }
    };

    device.create_pixel_shader(&bytecode)
}

fn bind_pipeline_state(device: &Device9Ref<'_>) -> Direct3DResult<()> {
    device.clear_vertex_shader()?;
    device.set_fvf(ScreenVertex::FVF)?;
    device.set_render_state(D3DRS_CULLMODE, D3DCULL_NONE.0 as u32)?;
    device.set_render_state(D3DRS_ALPHABLENDENABLE, 0)?;
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
    for sampler in [1, 2, 4] {
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

fn bind_fullres_constants(
    device: &Device9Ref<'_>,
    desc: &D3DSURFACE_DESC,
    frame_inputs: &FrameInputs,
    fast_source: Option<&ScreenShaderSource>,
    contact_source: Option<&ScreenShaderSource>,
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
                frame_inputs.depth.first_person_texture.is_some() as u8 as f32,
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

    bind_fast_constants(device, fast_source)?;

    bind_contact_constants(device, contact_source)?;

    device.set_pixel_shader_constant_f(
        6,
        &[[
            frame_inputs.environment.fog_start,
            frame_inputs.environment.fog_end,
            frame_inputs.environment.fog_power,
            frame_inputs.environment.fog_available_f32(),
        ]],
    )
}

fn bind_fast_constants(
    device: &Device9Ref<'_>,
    fast_source: Option<&ScreenShaderSource>,
) -> Direct3DResult<()> {
    let mut constants = [
        [0.0f32, 75.5, 7.6, 0.076],
        [0.0, 1.0, 0.18, 0.45],
        [0.65, 1.0, 1.0, 0.0],
    ];
    if let Some(source) = fast_source {
        for (index, source_constant) in source.option_constants.iter().take(3).enumerate() {
            constants[index] = *source_constant;
        }
    }
    device.set_pixel_shader_constant_f(3, &constants)
}

fn bind_contact_constants(
    device: &Device9Ref<'_>,
    contact_source: Option<&ScreenShaderSource>,
) -> Direct3DResult<()> {
    let mut constants = [
        [0.0f32, 4.3, 0.031, 0.0],
        [0.0, 1.0, 0.67, 0.63],
        [1.0, 1.0, 0.0, 0.0],
    ];
    if let Some(source) = contact_source {
        for (index, source_constant) in source.option_constants.iter().take(3).enumerate() {
            constants[index] = *source_constant;
        }
    }
    device.set_pixel_shader_constant_f(CONTACT_OPTION_REGISTER, &constants)
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

struct AmbientOcclusionTargets {
    width: u32,
    height: u32,
    inv_width: f32,
    inv_height: f32,
    occlusion: EffectTarget,
    blur: EffectTarget,
}

impl AmbientOcclusionTargets {
    fn create(
        device: &Device9Ref<'_>,
        width: u32,
        height: u32,
        fallback_format: D3DFORMAT,
    ) -> Direct3DResult<Self> {
        let (occlusion, blur) = match (
            EffectTarget::create(device, width, height, D3DFMT_G16R16F),
            EffectTarget::create(device, width, height, D3DFMT_G16R16F),
        ) {
            (Ok(occlusion), Ok(blur)) => (occlusion, blur),
            (Err(err), _) | (_, Err(err)) => {
                log::warn!(
                    "[AO] G16R16F targets unavailable ({err}); falling back to scene format"
                );
                (
                    EffectTarget::create(device, width, height, fallback_format)?,
                    EffectTarget::create(device, width, height, fallback_format)?,
                )
            }
        };

        Ok(Self {
            width,
            height,
            inv_width: 1.0 / width as f32,
            inv_height: 1.0 / height as f32,
            occlusion,
            blur,
        })
    }

    fn matches(&self, width: u32, height: u32) -> bool {
        self.width == width && self.height == height
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

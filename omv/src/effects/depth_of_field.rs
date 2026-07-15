//! Engine-side depth-of-field pipeline.

use std::{
    fs,
    mem::size_of,
    path::PathBuf,
    slice,
    sync::{
        LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use anyhow::Result;
use libpsycho::os::windows::directx9::{
    D3DCULL_NONE, D3DFMT_A16B16G16R16F, D3DFMT_G16R16F, D3DFMT_R16F, D3DFORMAT,
    D3DPT_TRIANGLESTRIP, D3DRS_ALPHABLENDENABLE, D3DRS_COLORWRITEENABLE, D3DRS_CULLMODE,
    D3DRS_ZENABLE, D3DRS_ZWRITEENABLE, D3DSAMP_ADDRESSU, D3DSAMP_ADDRESSV, D3DSAMP_MAGFILTER,
    D3DSAMP_MINFILTER, D3DSAMP_MIPFILTER, D3DSURFACE_DESC, D3DTA_TEXTURE, D3DTADDRESS_CLAMP,
    D3DTEXF_LINEAR, D3DTEXF_NONE, D3DTEXF_POINT, D3DTOP_SELECTARG1, D3DTSS_ALPHAARG1,
    D3DTSS_ALPHAOP, D3DTSS_COLORARG1, D3DTSS_COLOROP, D3DVIEWPORT9, Device9Ref, Direct3DResult,
    PixelShader9, ScreenVertex, Surface9, Texture9, direct3d_failure,
};
use parking_lot::Mutex;

use crate::{
    backend::{DepthTexture, FrameInputs},
    config::{DepthOfFieldConfig, DofBlurStyle, DofFocusMode, DofQuality},
    shaders,
};

const COLOR_WRITE_ALL: u32 = 0x0F;
const HALF_SCALE: u32 = 2;
const QUARTER_SCALE: u32 = 4;
const EIGHTH_SCALE: u32 = 8;
const NEAR_TILE_SIZE: u32 = 8;
const RESUME_SECONDS: f32 = 0.15;

const FOCUS_SHADER: &[u8] = include_bytes!("../../shaders/embedded/dof_focus.hlsl");
const COC_SHADER: &[u8] = include_bytes!("../../shaders/embedded/dof_coc.hlsl");
const PREFILTER_SHADER: &[u8] = include_bytes!("../../shaders/embedded/dof_prefilter.hlsl");
const NEAR_TILE_SHADER: &[u8] = include_bytes!("../../shaders/embedded/dof_near_tile.hlsl");
const DILATE_SHADER: &[u8] = include_bytes!("../../shaders/embedded/dof_near_dilate.hlsl");
const NEAR_SMOOTH_SHADER: &[u8] = include_bytes!("../../shaders/embedded/dof_near_smooth.hlsl");
const FAR_GATHER_SHADER: &[u8] = include_bytes!("../../shaders/embedded/dof_far_gather.hlsl");
const NEAR_GATHER_SHADER: &[u8] = include_bytes!("../../shaders/embedded/dof_near_gather.hlsl");
const DOWNSAMPLE_SHADER: &[u8] = include_bytes!("../../shaders/embedded/dof_downsample.hlsl");
const SOFT_RECONSTRUCT_SHADER: &[u8] =
    include_bytes!("../../shaders/embedded/dof_soft_reconstruct.hlsl");
const COMPOSE_SHADER: &[u8] = include_bytes!("../../shaders/embedded/dof_compose.hlsl");

static COMPILE_STARTED: AtomicBool = AtomicBool::new(false);
static COMPILE_FAILED: AtomicBool = AtomicBool::new(false);
static BYTECODE: LazyLock<Mutex<Option<DofBytecode>>> = LazyLock::new(|| Mutex::new(None));

struct DofBytecode {
    focus: Vec<u32>,
    coc: Vec<u32>,
    prefilter: Vec<u32>,
    near_tile: Vec<u32>,
    dilate: Vec<u32>,
    near_smooth: Vec<u32>,
    far_gather: GatherBytecode,
    near_gather: GatherBytecode,
    downsample: Vec<u32>,
    soft_reconstruct: SoftReconstructBytecode,
    compose: Vec<u32>,
}

struct GatherBytecode {
    balanced: Vec<u32>,
    high: Vec<u32>,
    ultra: Vec<u32>,
}

struct SoftReconstructBytecode {
    quarter: Vec<u32>,
    high: Vec<u32>,
    ultra: Vec<u32>,
}

impl DofBytecode {
    fn compile() -> Result<Self> {
        Ok(Self {
            focus: load_or_compile_shader("dof_focus.hlsl", FOCUS_SHADER)?,
            coc: load_or_compile_shader("dof_coc.hlsl", COC_SHADER)?,
            prefilter: load_or_compile_shader("dof_prefilter.hlsl", PREFILTER_SHADER)?,
            near_tile: load_or_compile_shader("dof_near_tile.hlsl", NEAR_TILE_SHADER)?,
            dilate: load_or_compile_shader("dof_near_dilate.hlsl", DILATE_SHADER)?,
            near_smooth: load_or_compile_shader("dof_near_smooth.hlsl", NEAR_SMOOTH_SHADER)?,
            far_gather: GatherBytecode::compile("dof_far_gather.hlsl", FAR_GATHER_SHADER)?,
            near_gather: GatherBytecode::compile("dof_near_gather.hlsl", NEAR_GATHER_SHADER)?,
            downsample: load_or_compile_shader("dof_downsample.hlsl", DOWNSAMPLE_SHADER)?,
            soft_reconstruct: SoftReconstructBytecode::compile()?,
            compose: load_or_compile_shader("dof_compose.hlsl", COMPOSE_SHADER)?,
        })
    }
}

impl SoftReconstructBytecode {
    fn compile() -> Result<Self> {
        Ok(Self {
            quarter: compile_soft_reconstruct_bytecode("quarter", false, false)?,
            high: compile_soft_reconstruct_bytecode("high", true, false)?,
            ultra: compile_soft_reconstruct_bytecode("ultra", true, true)?,
        })
    }
}

impl GatherBytecode {
    fn compile(source_name: &str, source: &[u8]) -> Result<Self> {
        Ok(Self {
            balanced: compile_gather_bytecode(source_name, source, 12)?,
            high: compile_gather_bytecode(source_name, source, 16)?,
            ultra: compile_gather_bytecode(source_name, source, 24)?,
        })
    }
}

pub(crate) fn service_present_frame() {
    start_compile_worker();
}

fn start_compile_worker() {
    if COMPILE_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    if let Err(err) = thread::Builder::new()
        .name("omv-dof-compile".to_owned())
        .spawn(|| match DofBytecode::compile() {
            Ok(bytecode) => *BYTECODE.lock() = Some(bytecode),
            Err(err) => {
                COMPILE_FAILED.store(true, Ordering::Release);
                log::warn!("[DOF] Shader preparation failed: {err:#}");
            }
        })
    {
        COMPILE_FAILED.store(true, Ordering::Release);
        log::warn!("[DOF] Could not start shader preparation: {err}");
    }
}

pub(crate) struct DepthOfFieldEffect {
    focus_shader: PixelShader9,
    coc_shader: PixelShader9,
    prefilter_shader: PixelShader9,
    near_tile_shader: PixelShader9,
    dilate_shader: PixelShader9,
    near_smooth_shader: PixelShader9,
    far_gather_shaders: GatherShaders,
    near_gather_shaders: GatherShaders,
    downsample_shader: PixelShader9,
    soft_reconstruct_shaders: SoftReconstructShaders,
    compose_shader: PixelShader9,
    scalar_format: D3DFORMAT,
    targets: Option<DofTargets>,
    failed_target_size: Option<(u32, u32)>,
    focus_a_is_current: bool,
    focus_history_valid: bool,
    resume_mix: f32,
}

impl DepthOfFieldEffect {
    pub(crate) fn create(device: &Device9Ref<'_>) -> Direct3DResult<Option<Self>> {
        start_compile_worker();
        if COMPILE_FAILED.load(Ordering::Acquire) {
            return Err(direct3d_failure());
        }
        let bytecode = BYTECODE.lock();
        let Some(bytecode) = bytecode.as_ref() else {
            return Ok(None);
        };
        let direct3d = device.direct3d()?;
        direct3d.check_default_render_target_texture_support(D3DFMT_A16B16G16R16F)?;
        let scalar_format = if direct3d
            .check_default_render_target_texture_support(D3DFMT_R16F)
            .is_ok()
        {
            D3DFMT_R16F
        } else {
            direct3d.check_default_render_target_texture_support(D3DFMT_G16R16F)?;
            D3DFMT_G16R16F
        };

        Ok(Some(Self {
            focus_shader: device.create_pixel_shader(&bytecode.focus)?,
            coc_shader: device.create_pixel_shader(&bytecode.coc)?,
            prefilter_shader: device.create_pixel_shader(&bytecode.prefilter)?,
            near_tile_shader: device.create_pixel_shader(&bytecode.near_tile)?,
            dilate_shader: device.create_pixel_shader(&bytecode.dilate)?,
            near_smooth_shader: device.create_pixel_shader(&bytecode.near_smooth)?,
            far_gather_shaders: GatherShaders::create(device, &bytecode.far_gather)?,
            near_gather_shaders: GatherShaders::create(device, &bytecode.near_gather)?,
            downsample_shader: device.create_pixel_shader(&bytecode.downsample)?,
            soft_reconstruct_shaders: SoftReconstructShaders::create(
                device,
                &bytecode.soft_reconstruct,
            )?,
            compose_shader: device.create_pixel_shader(&bytecode.compose)?,
            scalar_format,
            targets: None,
            failed_target_size: None,
            focus_a_is_current: true,
            focus_history_valid: false,
            resume_mix: 1.0,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn draw(
        &mut self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &FrameInputs,
        config: DepthOfFieldConfig,
        scene_color: &Texture9,
        frame_index: u32,
        frame_seconds: f32,
        native_dof_active: bool,
    ) -> Direct3DResult<()> {
        let settings = DofSettings::from_config(config);
        if settings.respect_vanilla_dof && native_dof_active {
            self.resume_mix = 0.0;
            return Ok(());
        }
        if frame_inputs.depth.texture.is_none()
            || !frame_inputs.depth.world_projection.camera.available
            || frame_inputs.depth.world_projection.reversed_depth.is_none()
        {
            return Ok(());
        }

        let frame_seconds = finite(frame_seconds, 1.0 / 60.0).clamp(1.0 / 240.0, 0.1);
        if settings.respect_vanilla_dof {
            let alpha = 1.0 - (-frame_seconds / RESUME_SECONDS).exp();
            self.resume_mix += (1.0 - self.resume_mix) * alpha;
        } else {
            self.resume_mix = 1.0;
        }

        let near_enabled = settings.near_enabled();
        let far_enabled = settings.far_enabled();
        if !near_enabled && !far_enabled {
            return Ok(());
        }
        let soft_pyramid = settings.blur_style == DofBlurStyle::Soft;
        self.ensure_targets(device, desc)?;
        bind_pipeline_state(device)?;

        let previous_focus_is_a = self.focus_a_is_current;
        {
            let Some(targets) = self.targets.as_ref() else {
                return Ok(());
            };
            let (previous_focus, next_focus) = targets.focus_pair(previous_focus_is_a);
            draw_focus(
                device,
                &self.focus_shader,
                &next_focus.surface,
                previous_focus,
                desc,
                frame_inputs,
                settings,
                frame_index,
                frame_seconds,
                self.resume_mix,
                self.focus_history_valid,
            )?;
        }
        self.focus_a_is_current = !previous_focus_is_a;
        self.focus_history_valid = true;

        let Some(targets) = self.targets.as_ref() else {
            return Ok(());
        };
        let focus_texture = targets.current_focus(self.focus_a_is_current);
        draw_coc(
            device,
            &self.coc_shader,
            targets,
            desc,
            frame_inputs,
            settings,
            focus_texture,
            frame_index,
            frame_seconds,
            self.resume_mix,
        )?;
        draw_prefilter(
            device,
            &self.prefilter_shader,
            targets,
            desc,
            frame_inputs,
            settings,
            scene_color,
            frame_index,
            frame_seconds,
            self.resume_mix,
        )?;
        if near_enabled {
            draw_near_mask(
                device,
                &self.near_tile_shader,
                &self.dilate_shader,
                &self.near_smooth_shader,
                targets,
                desc,
                settings,
            )?;
        }
        if far_enabled && !soft_pyramid {
            draw_far_gather(
                device,
                self.far_gather_shaders.shader(settings.quality),
                targets,
                desc,
                frame_inputs,
                settings,
                frame_index,
                frame_seconds,
                self.resume_mix,
            )?;
        }
        if near_enabled {
            draw_near_gather(
                device,
                self.near_gather_shaders.shader(settings.quality),
                targets,
                desc,
                frame_inputs,
                settings,
                frame_index,
                frame_seconds,
                self.resume_mix,
            )?;
        }
        if soft_pyramid {
            draw_soft_pyramid(
                device,
                &self.downsample_shader,
                &self.soft_reconstruct_shaders,
                targets,
                desc,
                settings,
                far_enabled,
                near_enabled,
            )?;
        }
        draw_compose(
            device,
            &self.compose_shader,
            backbuffer,
            desc,
            targets,
            frame_inputs,
            settings,
            scene_color,
            frame_index,
            frame_seconds,
            self.resume_mix,
            soft_pyramid,
        )
    }

    fn ensure_targets(
        &mut self,
        device: &Device9Ref<'_>,
        desc: &D3DSURFACE_DESC,
    ) -> Direct3DResult<()> {
        let size = (desc.Width, desc.Height);
        let needs_targets = self
            .targets
            .as_ref()
            .is_none_or(|targets| !targets.matches(desc.Width, desc.Height, self.scalar_format));

        if needs_targets {
            if self.failed_target_size == Some(size) {
                return Ok(());
            }
            match DofTargets::create(device, desc.Width, desc.Height, self.scalar_format) {
                Ok(targets) => {
                    self.targets = Some(targets);
                    self.failed_target_size = None;
                    self.focus_history_valid = false;
                    log::info!(
                        "[DOF] Intermediate targets: full={}x{}, half={}x{}",
                        desc.Width,
                        desc.Height,
                        (desc.Width + 1) / HALF_SCALE,
                        (desc.Height + 1) / HALF_SCALE
                    );
                }
                Err(err) => {
                    self.targets = None;
                    self.failed_target_size = Some(size);
                    return Err(err);
                }
            }
        }

        self.targets
            .as_ref()
            .map(|_| ())
            .ok_or_else(direct3d_failure)
    }
}

struct GatherShaders {
    balanced: PixelShader9,
    high: PixelShader9,
    ultra: PixelShader9,
}

impl GatherShaders {
    fn create(device: &Device9Ref<'_>, bytecode: &GatherBytecode) -> Direct3DResult<Self> {
        Ok(Self {
            balanced: device.create_pixel_shader(&bytecode.balanced)?,
            high: device.create_pixel_shader(&bytecode.high)?,
            ultra: device.create_pixel_shader(&bytecode.ultra)?,
        })
    }

    fn shader(&self, quality: DofQuality) -> &PixelShader9 {
        match quality {
            DofQuality::Balanced => &self.balanced,
            DofQuality::High => &self.high,
            DofQuality::Ultra => &self.ultra,
        }
    }
}

struct SoftReconstructShaders {
    quarter: PixelShader9,
    high: PixelShader9,
    ultra: PixelShader9,
}

impl SoftReconstructShaders {
    fn create(device: &Device9Ref<'_>, bytecode: &SoftReconstructBytecode) -> Direct3DResult<Self> {
        Ok(Self {
            quarter: device.create_pixel_shader(&bytecode.quarter)?,
            high: device.create_pixel_shader(&bytecode.high)?,
            ultra: device.create_pixel_shader(&bytecode.ultra)?,
        })
    }

    fn shader(&self, quality: DofQuality, use_eighth: bool) -> &PixelShader9 {
        if !use_eighth {
            return &self.quarter;
        }
        match quality {
            DofQuality::Ultra => &self.ultra,
            DofQuality::Balanced | DofQuality::High => &self.high,
        }
    }
}

#[derive(Clone, Copy)]
struct DofSettings {
    respect_vanilla_dof: bool,
    focus_mode: DofFocusMode,
    quality: DofQuality,
    blur_style: DofBlurStyle,
    manual_focus_distance: f32,
    focus_sample_radius: f32,
    focus_cluster_tolerance: f32,
    focus_deadband: f32,
    focus_near_seconds: f32,
    focus_far_seconds: f32,
    focus_range: f32,
    far_focus_range: f32,
    near_strength: f32,
    far_strength: f32,
    near_radius_pixels: f32,
    far_radius_pixels: f32,
    first_person_strength: f32,
    distant_blur_strength: f32,
    distant_blur_start: f32,
    distant_blur_end: f32,
    sky_blur_strength: f32,
    softness: f32,
}

impl DofSettings {
    fn from_config(config: DepthOfFieldConfig) -> Self {
        let distant_blur_start = finite(config.distant_blur_start, 30_000.0).clamp(1.0, 500_000.0);
        let distant_blur_end =
            finite(config.distant_blur_end, 150_000.0).clamp(distant_blur_start + 1.0, 1_000_000.0);
        Self {
            respect_vanilla_dof: config.respect_vanilla_dof,
            focus_mode: config.focus_mode,
            quality: config.quality,
            blur_style: config.blur_style,
            manual_focus_distance: finite(config.manual_focus_distance, 2_000.0)
                .clamp(1.0, 1_000_000.0),
            focus_sample_radius: finite(config.focus_sample_radius, 0.055).clamp(0.0, 0.25),
            focus_cluster_tolerance: finite(config.focus_cluster_tolerance, 0.18).clamp(0.01, 1.0),
            focus_deadband: finite(config.focus_deadband, 0.025).clamp(0.0, 0.25),
            focus_near_seconds: finite(config.focus_near_seconds, 0.12).clamp(0.01, 2.0),
            focus_far_seconds: finite(config.focus_far_seconds, 0.28).clamp(0.01, 3.0),
            focus_range: finite(config.focus_range, 0.12).clamp(0.01, 2.0),
            far_focus_range: finite(config.far_focus_range, 0.16).clamp(0.01, 2.0),
            near_strength: finite(config.near_strength, 0.85).clamp(0.0, 2.0),
            far_strength: finite(config.far_strength, 0.75).clamp(0.0, 2.0),
            near_radius_pixels: finite(config.near_radius_pixels, 12.0).clamp(0.0, 96.0),
            far_radius_pixels: finite(config.far_radius_pixels, 36.0).clamp(0.0, 128.0),
            first_person_strength: finite(config.first_person_strength, 0.4).clamp(0.0, 1.0),
            distant_blur_strength: finite(config.distant_blur_strength, 0.65).clamp(0.0, 2.0),
            distant_blur_start,
            distant_blur_end,
            sky_blur_strength: finite(config.sky_blur_strength, 0.0).clamp(0.0, 1.0),
            softness: finite(config.softness, 0.75).clamp(0.0, 1.0),
        }
    }

    fn near_enabled(self) -> bool {
        self.near_strength > 0.001 && self.near_radius_pixels > 0.001
    }

    fn far_enabled(self) -> bool {
        self.far_radius_pixels > 0.001
            && (self.far_strength > 0.001
                || self.distant_blur_strength > 0.001
                || self.sky_blur_strength > 0.001)
    }
}

fn finite(value: f32, fallback: f32) -> f32 {
    if value.is_finite() { value } else { fallback }
}

#[allow(clippy::too_many_arguments)]
fn draw_focus(
    device: &Device9Ref<'_>,
    shader: &PixelShader9,
    output: &Surface9,
    previous_focus: &Texture9,
    desc: &D3DSURFACE_DESC,
    frame_inputs: &FrameInputs,
    settings: DofSettings,
    frame_index: u32,
    frame_seconds: f32,
    resume_mix: f32,
    focus_history_valid: bool,
) -> Direct3DResult<()> {
    bind_target(device, output, 1, 1)?;
    device.set_texture(0, previous_focus)?;
    bind_depth_texture(device, 1, &frame_inputs.depth.texture)?;
    set_sampler_filter(device, 1, D3DTEXF_POINT.0 as u32)?;
    bind_constants(
        device,
        desc,
        1,
        1,
        frame_inputs,
        settings,
        frame_index,
        frame_seconds,
        resume_mix,
        focus_history_valid,
    )?;
    device.set_pixel_shader(shader)?;
    draw_quad(device, 1, 1)
}

#[allow(clippy::too_many_arguments)]
fn draw_coc(
    device: &Device9Ref<'_>,
    shader: &PixelShader9,
    targets: &DofTargets,
    desc: &D3DSURFACE_DESC,
    frame_inputs: &FrameInputs,
    settings: DofSettings,
    focus_texture: &Texture9,
    frame_index: u32,
    frame_seconds: f32,
    resume_mix: f32,
) -> Direct3DResult<()> {
    bind_target(
        device,
        &targets.full_coc.surface,
        targets.full_width,
        targets.full_height,
    )?;
    bind_depth_texture(device, 0, &frame_inputs.depth.texture)?;
    bind_depth_texture(device, 1, &frame_inputs.depth.first_person_texture)?;
    device.set_texture(2, focus_texture)?;
    set_sampler_filter(device, 0, D3DTEXF_POINT.0 as u32)?;
    set_sampler_filter(device, 1, D3DTEXF_POINT.0 as u32)?;
    set_sampler_filter(device, 2, D3DTEXF_POINT.0 as u32)?;
    bind_constants(
        device,
        desc,
        targets.full_width,
        targets.full_height,
        frame_inputs,
        settings,
        frame_index,
        frame_seconds,
        resume_mix,
        true,
    )?;
    device.set_pixel_shader(shader)?;
    draw_quad(device, targets.full_width, targets.full_height)
}

#[allow(clippy::too_many_arguments)]
fn draw_prefilter(
    device: &Device9Ref<'_>,
    shader: &PixelShader9,
    targets: &DofTargets,
    desc: &D3DSURFACE_DESC,
    frame_inputs: &FrameInputs,
    settings: DofSettings,
    scene_color: &Texture9,
    frame_index: u32,
    frame_seconds: f32,
    resume_mix: f32,
) -> Direct3DResult<()> {
    bind_target(
        device,
        &targets.prefilter.surface,
        targets.half_width,
        targets.half_height,
    )?;
    device.set_texture(0, scene_color)?;
    device.set_texture(1, &targets.full_coc.texture)?;
    set_sampler_filter(device, 0, D3DTEXF_LINEAR.0 as u32)?;
    set_sampler_filter(device, 1, D3DTEXF_POINT.0 as u32)?;
    bind_constants(
        device,
        desc,
        targets.half_width,
        targets.half_height,
        frame_inputs,
        settings,
        frame_index,
        frame_seconds,
        resume_mix,
        true,
    )?;
    device.set_pixel_shader(shader)?;
    draw_quad(device, targets.half_width, targets.half_height)
}

fn draw_near_mask(
    device: &Device9Ref<'_>,
    tile_shader: &PixelShader9,
    dilate_shader: &PixelShader9,
    smooth_shader: &PixelShader9,
    targets: &DofTargets,
    desc: &D3DSURFACE_DESC,
    settings: DofSettings,
) -> Direct3DResult<()> {
    let radius_scale = desc.Height as f32 / 1080.0;
    let radius = settings.near_radius_pixels * radius_scale;

    bind_target(
        device,
        &targets.near_tile_rows.surface,
        targets.near_tile_rows.width,
        targets.near_tile_rows.height,
    )?;
    device.set_texture(0, &targets.full_coc.texture)?;
    set_sampler_filter(device, 0, D3DTEXF_POINT.0 as u32)?;
    device.set_pixel_shader_constant_f(
        9,
        &[[
            1.0 / desc.Width.max(1) as f32,
            1.0 / desc.Height.max(1) as f32,
            targets.near_tile_rows.width as f32,
            targets.near_tile_rows.height as f32,
        ]],
    )?;
    device.set_pixel_shader_constant_f(10, &[[1.0, 0.0, 0.0, 0.0]])?;
    device.set_pixel_shader(tile_shader)?;
    draw_quad(
        device,
        targets.near_tile_rows.width,
        targets.near_tile_rows.height,
    )?;

    bind_target(
        device,
        &targets.near_tile.surface,
        targets.near_tile.width,
        targets.near_tile.height,
    )?;
    device.set_texture(0, &targets.near_tile_rows.texture)?;
    set_sampler_filter(device, 0, D3DTEXF_POINT.0 as u32)?;
    device.set_pixel_shader_constant_f(
        9,
        &[[
            targets.near_tile_rows.inv_width,
            targets.near_tile_rows.inv_height,
            targets.near_tile.width as f32,
            targets.near_tile.height as f32,
        ]],
    )?;
    device.set_pixel_shader_constant_f(10, &[[0.0, 0.0, 0.0, 0.0]])?;
    device.set_pixel_shader(tile_shader)?;
    draw_quad(device, targets.near_tile.width, targets.near_tile.height)?;

    bind_target(
        device,
        &targets.near_tile_temp.surface,
        targets.near_tile_temp.width,
        targets.near_tile_temp.height,
    )?;
    device.set_texture(0, &targets.near_tile.texture)?;
    set_sampler_filter(device, 0, D3DTEXF_LINEAR.0 as u32)?;
    device.set_pixel_shader_constant_f(9, &[[radius / desc.Width.max(1) as f32, 0.0, 1.0, 0.0]])?;
    device.set_pixel_shader_constant_f(10, &[[0.0, targets.near_tile.inv_height, 0.0, 0.0]])?;
    device.set_pixel_shader(dilate_shader)?;
    draw_quad(
        device,
        targets.near_tile_temp.width,
        targets.near_tile_temp.height,
    )?;

    bind_target(
        device,
        &targets.near_tile_expanded.surface,
        targets.near_tile_expanded.width,
        targets.near_tile_expanded.height,
    )?;
    device.set_texture(0, &targets.near_tile_temp.texture)?;
    set_sampler_filter(device, 0, D3DTEXF_LINEAR.0 as u32)?;
    device
        .set_pixel_shader_constant_f(9, &[[0.0, radius / desc.Height.max(1) as f32, 1.0, 0.0]])?;
    device.set_pixel_shader_constant_f(10, &[[targets.near_tile.inv_width, 0.0, 0.0, 0.0]])?;
    device.set_pixel_shader(dilate_shader)?;
    draw_quad(
        device,
        targets.near_tile_expanded.width,
        targets.near_tile_expanded.height,
    )?;

    bind_target(
        device,
        &targets.near_coc.surface,
        targets.half_width,
        targets.half_height,
    )?;
    device.set_texture(0, &targets.full_coc.texture)?;
    device.set_texture(1, &targets.near_tile_expanded.texture)?;
    set_sampler_filter(device, 0, D3DTEXF_POINT.0 as u32)?;
    set_sampler_filter(device, 1, D3DTEXF_LINEAR.0 as u32)?;
    device.set_pixel_shader(smooth_shader)?;
    draw_quad(device, targets.half_width, targets.half_height)
}

#[allow(clippy::too_many_arguments)]
fn draw_far_gather(
    device: &Device9Ref<'_>,
    shader: &PixelShader9,
    targets: &DofTargets,
    desc: &D3DSURFACE_DESC,
    frame_inputs: &FrameInputs,
    settings: DofSettings,
    frame_index: u32,
    frame_seconds: f32,
    resume_mix: f32,
) -> Direct3DResult<()> {
    bind_target(
        device,
        &targets.far.surface,
        targets.half_width,
        targets.half_height,
    )?;
    device.set_texture(0, &targets.prefilter.texture)?;
    device.set_texture(1, &targets.full_coc.texture)?;
    set_sampler_filter(device, 0, D3DTEXF_LINEAR.0 as u32)?;
    set_sampler_filter(device, 1, D3DTEXF_POINT.0 as u32)?;
    bind_constants(
        device,
        desc,
        targets.half_width,
        targets.half_height,
        frame_inputs,
        settings,
        frame_index,
        frame_seconds,
        resume_mix,
        true,
    )?;
    device.set_pixel_shader(shader)?;
    draw_quad(device, targets.half_width, targets.half_height)
}

#[allow(clippy::too_many_arguments)]
fn draw_near_gather(
    device: &Device9Ref<'_>,
    shader: &PixelShader9,
    targets: &DofTargets,
    desc: &D3DSURFACE_DESC,
    frame_inputs: &FrameInputs,
    settings: DofSettings,
    frame_index: u32,
    frame_seconds: f32,
    resume_mix: f32,
) -> Direct3DResult<()> {
    bind_target(
        device,
        &targets.near.surface,
        targets.half_width,
        targets.half_height,
    )?;
    device.set_texture(0, &targets.prefilter.texture)?;
    device.set_texture(1, &targets.near_coc.texture)?;
    device.set_texture(2, &targets.full_coc.texture)?;
    set_sampler_filter(device, 0, D3DTEXF_LINEAR.0 as u32)?;
    set_sampler_filter(device, 1, D3DTEXF_LINEAR.0 as u32)?;
    set_sampler_filter(device, 2, D3DTEXF_POINT.0 as u32)?;
    bind_constants(
        device,
        desc,
        targets.half_width,
        targets.half_height,
        frame_inputs,
        settings,
        frame_index,
        frame_seconds,
        resume_mix,
        true,
    )?;
    device.set_pixel_shader(shader)?;
    draw_quad(device, targets.half_width, targets.half_height)
}

#[allow(clippy::too_many_arguments)]
fn draw_soft_pyramid(
    device: &Device9Ref<'_>,
    downsample_shader: &PixelShader9,
    reconstruct_shaders: &SoftReconstructShaders,
    targets: &DofTargets,
    desc: &D3DSURFACE_DESC,
    settings: DofSettings,
    far_enabled: bool,
    near_enabled: bool,
) -> Direct3DResult<()> {
    let use_eighth = settings.quality != DofQuality::Balanced && settings.softness > 0.3;
    let reconstruct_shader = reconstruct_shaders.shader(settings.quality, use_eighth);
    let radius_scale = desc.Height as f32 / 1080.0;
    if far_enabled {
        draw_soft_layer(
            device,
            downsample_shader,
            reconstruct_shader,
            targets,
            &targets.prefilter.texture,
            &targets.far.surface,
            settings.softness,
            settings.far_radius_pixels * radius_scale,
            use_eighth,
        )?;
    }
    if near_enabled {
        draw_soft_layer(
            device,
            downsample_shader,
            reconstruct_shader,
            targets,
            &targets.near.texture,
            &targets.prefilter.surface,
            settings.softness,
            settings.near_radius_pixels * radius_scale * 0.5,
            use_eighth,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn draw_soft_layer(
    device: &Device9Ref<'_>,
    downsample_shader: &PixelShader9,
    reconstruct_shader: &PixelShader9,
    targets: &DofTargets,
    source: &Texture9,
    output: &Surface9,
    softness: f32,
    radius_pixels: f32,
    use_eighth: bool,
) -> Direct3DResult<()> {
    let quarter = &targets.quarter;
    let eighth = &targets.eighth;
    let quarter_downsample_spread = (radius_pixels / 32.0).clamp(0.5, 3.0);
    let eighth_downsample_spread = (radius_pixels / 64.0).clamp(0.5, 2.0);
    let quarter_reconstruct_spread = if use_eighth {
        radius_pixels / 8.0
    } else {
        radius_pixels / 4.0
    }
    .max(0.5);
    let eighth_reconstruct_spread = (radius_pixels / 8.0).max(0.5);

    bind_target(device, &quarter.surface, quarter.width, quarter.height)?;
    device.set_texture(0, source)?;
    set_sampler_filter(device, 0, D3DTEXF_LINEAR.0 as u32)?;
    device.set_pixel_shader_constant_f(
        9,
        &[[
            targets.half_inv_width * quarter_downsample_spread,
            targets.half_inv_height * quarter_downsample_spread,
            0.0,
            0.0,
        ]],
    )?;
    device.set_pixel_shader(downsample_shader)?;
    draw_quad(device, quarter.width, quarter.height)?;

    if use_eighth {
        bind_target(device, &eighth.surface, eighth.width, eighth.height)?;
        device.set_texture(0, &quarter.texture)?;
        set_sampler_filter(device, 0, D3DTEXF_LINEAR.0 as u32)?;
        device.set_pixel_shader_constant_f(
            9,
            &[[
                quarter.inv_width * eighth_downsample_spread,
                quarter.inv_height * eighth_downsample_spread,
                0.0,
                0.0,
            ]],
        )?;
        device.set_pixel_shader(downsample_shader)?;
        draw_quad(device, eighth.width, eighth.height)?;
    }

    bind_target(device, output, targets.half_width, targets.half_height)?;
    device.set_texture(0, source)?;
    device.set_texture(1, &quarter.texture)?;
    device.set_texture(
        2,
        if use_eighth {
            &eighth.texture
        } else {
            &quarter.texture
        },
    )?;
    set_sampler_filter(device, 0, D3DTEXF_LINEAR.0 as u32)?;
    set_sampler_filter(device, 1, D3DTEXF_LINEAR.0 as u32)?;
    set_sampler_filter(device, 2, D3DTEXF_LINEAR.0 as u32)?;
    device.set_pixel_shader_constant_f(
        9,
        &[[
            quarter.inv_width * quarter_reconstruct_spread,
            quarter.inv_height * quarter_reconstruct_spread,
            if use_eighth {
                eighth.inv_width * eighth_reconstruct_spread
            } else {
                0.0
            },
            if use_eighth {
                eighth.inv_height * eighth_reconstruct_spread
            } else {
                0.0
            },
        ]],
    )?;
    device.set_pixel_shader_constant_f(
        10,
        &[[
            targets.half_inv_width,
            targets.half_inv_height,
            softness,
            0.0,
        ]],
    )?;
    device.set_pixel_shader(reconstruct_shader)?;
    draw_quad(device, targets.half_width, targets.half_height)
}

#[allow(clippy::too_many_arguments)]
fn draw_compose(
    device: &Device9Ref<'_>,
    shader: &PixelShader9,
    backbuffer: &Surface9,
    desc: &D3DSURFACE_DESC,
    targets: &DofTargets,
    frame_inputs: &FrameInputs,
    settings: DofSettings,
    scene_color: &Texture9,
    frame_index: u32,
    frame_seconds: f32,
    resume_mix: f32,
    soft_reconstruction: bool,
) -> Direct3DResult<()> {
    bind_target(device, backbuffer, desc.Width, desc.Height)?;
    device.set_texture(0, scene_color)?;
    if soft_reconstruction {
        device.set_texture(1, &targets.far.texture)?;
        device.set_texture(2, &targets.prefilter.texture)?;
    } else {
        device.set_texture(1, &targets.far.texture)?;
        device.set_texture(2, &targets.near.texture)?;
    }
    device.set_texture(3, &targets.full_coc.texture)?;
    device.set_texture(4, &targets.near_coc.texture)?;
    set_sampler_filter(device, 0, D3DTEXF_LINEAR.0 as u32)?;
    set_sampler_filter(device, 1, D3DTEXF_LINEAR.0 as u32)?;
    set_sampler_filter(device, 2, D3DTEXF_LINEAR.0 as u32)?;
    set_sampler_filter(device, 3, D3DTEXF_POINT.0 as u32)?;
    set_sampler_filter(device, 4, D3DTEXF_LINEAR.0 as u32)?;
    bind_constants(
        device,
        desc,
        desc.Width,
        desc.Height,
        frame_inputs,
        settings,
        frame_index,
        frame_seconds,
        resume_mix,
        true,
    )?;
    device.set_pixel_shader_constant_f(
        9,
        &[[
            targets.half_inv_width,
            targets.half_inv_height,
            targets.half_width as f32,
            targets.half_height as f32,
        ]],
    )?;
    device.set_pixel_shader(shader)?;
    draw_quad(device, desc.Width, desc.Height)
}

fn load_or_compile_shader(source_name: &str, source: &[u8]) -> Result<Vec<u32>> {
    let hash = shader_source_hash(source_name, source);
    let path = shader_cache_path(source_name, hash);
    if let Ok(bytes) = fs::read(&path)
        && let Some(bytecode) = decode_cached_shader(&bytes)
    {
        return Ok(bytecode);
    }

    let bytecode = shaders::compile_hlsl_source(source_name, source)?;
    if let Some(parent) = path.parent()
        && fs::create_dir_all(parent).is_ok()
    {
        let bytes = unsafe {
            slice::from_raw_parts(
                bytecode.as_ptr().cast::<u8>(),
                bytecode.len() * size_of::<u32>(),
            )
        };
        let _ = fs::write(path, bytes);
    }
    Ok(bytecode)
}

fn shader_source_hash(source_name: &str, source: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in source_name.as_bytes().iter().chain(b"ps_3_0").chain(source) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn shader_cache_path(source_name: &str, hash: u64) -> PathBuf {
    let mut path = PathBuf::from(crate::config::CONFIG_PATH);
    let _ = path.pop();
    path.push("cache");
    path.push("depth_of_field");
    let label: String = source_name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect();
    path.push(format!("{label}_{hash:016x}.cso"));
    path
}

fn decode_cached_shader(bytes: &[u8]) -> Option<Vec<u32>> {
    if bytes.len() < size_of::<u32>() || !bytes.len().is_multiple_of(size_of::<u32>()) {
        return None;
    }
    let version = u32::from_le_bytes(bytes[..4].try_into().ok()?);
    if version != 0xFFFF_0300 {
        return None;
    }
    Some(
        bytes
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().expect("four-byte shader word")))
            .collect(),
    )
}

fn compile_gather_bytecode(source_name: &str, source: &[u8], tap_count: u32) -> Result<Vec<u32>> {
    let mut variant = format!("#define DOF_TAP_COUNT {tap_count}\n").into_bytes();
    variant.extend_from_slice(source);
    load_or_compile_shader(&format!("{source_name}:{tap_count}"), &variant)
}

fn compile_soft_reconstruct_bytecode(
    label: &str,
    use_eighth: bool,
    ultra: bool,
) -> Result<Vec<u32>> {
    let mut variant = format!(
        "#define DOF_USE_EIGHTH {}\n#define DOF_ULTRA {}\n",
        use_eighth as u8, ultra as u8
    )
    .into_bytes();
    variant.extend_from_slice(SOFT_RECONSTRUCT_SHADER);
    load_or_compile_shader(&format!("dof_soft_reconstruct.hlsl:{label}"), &variant)
}

fn bind_pipeline_state(device: &Device9Ref<'_>) -> Direct3DResult<()> {
    device.clear_vertex_shader()?;
    device.set_fvf(ScreenVertex::FVF)?;
    device.set_render_state(D3DRS_CULLMODE, D3DCULL_NONE.0 as u32)?;
    device.set_render_state(D3DRS_ALPHABLENDENABLE, 0)?;
    device.set_render_state(D3DRS_ZENABLE, 0)?;
    device.set_render_state(D3DRS_ZWRITEENABLE, 0)?;
    device.set_render_state(D3DRS_COLORWRITEENABLE, COLOR_WRITE_ALL)?;
    for sampler in 0..=9 {
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
    device.set_texture_stage_state(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE)
}

fn bind_target(
    device: &Device9Ref<'_>,
    surface: &Surface9,
    width: u32,
    height: u32,
) -> Direct3DResult<()> {
    for sampler in 0..=9 {
        device.clear_texture(sampler)?;
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

fn bind_depth_texture(
    device: &Device9Ref<'_>,
    sampler: u32,
    texture: &Option<DepthTexture>,
) -> Direct3DResult<()> {
    if let Some(texture) = texture {
        unsafe { device.set_raw_base_texture(sampler, texture.as_ptr()) }
    } else {
        device.clear_texture(sampler)
    }
}

fn set_sampler_filter(device: &Device9Ref<'_>, sampler: u32, filter: u32) -> Direct3DResult<()> {
    device.set_sampler_state(sampler, D3DSAMP_MINFILTER, filter)?;
    device.set_sampler_state(sampler, D3DSAMP_MAGFILTER, filter)
}

#[allow(clippy::too_many_arguments)]
fn bind_constants(
    device: &Device9Ref<'_>,
    desc: &D3DSURFACE_DESC,
    target_width: u32,
    target_height: u32,
    frame_inputs: &FrameInputs,
    settings: DofSettings,
    frame_index: u32,
    frame_seconds: f32,
    resume_mix: f32,
    focus_history_valid: bool,
) -> Direct3DResult<()> {
    let world = frame_inputs.depth.world_projection;
    let first_person = frame_inputs.depth.first_person_projection;
    let world_camera = world.camera;
    let first_person_camera = first_person.camera;
    let radius_scale = desc.Height as f32 / 1080.0;

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
                frame_index as f32,
                frame_seconds,
                resume_mix,
                focus_history_valid as u8 as f32,
            ],
            [
                world_camera.near_z,
                world_camera.far_z,
                world_camera.aspect_ratio,
                frame_inputs.depth.is_available() as u8 as f32,
            ],
            [
                settings.manual_focus_distance,
                settings.focus_sample_radius,
                settings.focus_cluster_tolerance,
                settings.focus_deadband,
            ],
            [
                settings.focus_near_seconds,
                settings.focus_far_seconds,
                settings.focus_range,
                (settings.focus_mode == DofFocusMode::Manual) as u8 as f32,
            ],
            [
                settings.near_strength,
                settings.far_strength,
                settings.first_person_strength,
                settings.distant_blur_strength,
            ],
            [
                settings.near_radius_pixels * radius_scale,
                settings.far_radius_pixels * radius_scale,
                settings.softness,
                settings.sky_blur_strength,
            ],
            [
                settings.distant_blur_start,
                settings.distant_blur_end,
                (settings.blur_style == DofBlurStyle::Soft) as u8 as f32,
                settings.far_focus_range,
            ],
            [
                target_width as f32,
                target_height as f32,
                1.0 / target_width.max(1) as f32,
                1.0 / target_height.max(1) as f32,
            ],
        ],
    )?;
    device.set_pixel_shader_constant_f(
        11,
        &[
            [
                world.reversed_depth_f32(),
                first_person.reversed_depth_f32(),
                world_camera.available_f32(),
                first_person_camera.available_f32(),
            ],
            [
                world_camera.frustum_left,
                world_camera.frustum_right,
                world_camera.frustum_bottom,
                world_camera.frustum_top,
            ],
            [
                first_person_camera.near_z,
                world_camera.far_z,
                first_person_camera.aspect_ratio,
                frame_inputs.depth.first_person_texture.is_some() as u8 as f32,
            ],
            [
                first_person_camera.frustum_left,
                first_person_camera.frustum_right,
                first_person_camera.frustum_bottom,
                first_person_camera.frustum_top,
            ],
        ],
    )
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

struct DofTargets {
    full_width: u32,
    full_height: u32,
    half_width: u32,
    half_height: u32,
    half_inv_width: f32,
    half_inv_height: f32,
    scalar_format: D3DFORMAT,
    full_coc: EffectTarget,
    prefilter: EffectTarget,
    far: EffectTarget,
    near: EffectTarget,
    near_tile_rows: SizedTarget,
    near_tile: SizedTarget,
    near_tile_temp: SizedTarget,
    near_tile_expanded: SizedTarget,
    near_coc: EffectTarget,
    focus_a: EffectTarget,
    focus_b: EffectTarget,
    quarter: SizedTarget,
    eighth: SizedTarget,
}

impl DofTargets {
    fn create(
        device: &Device9Ref<'_>,
        full_width: u32,
        full_height: u32,
        scalar_format: D3DFORMAT,
    ) -> Direct3DResult<Self> {
        let half_width = full_width.div_ceil(HALF_SCALE).max(1);
        let half_height = full_height.div_ceil(HALF_SCALE).max(1);
        let tile_width = full_width.div_ceil(NEAR_TILE_SIZE).max(1);
        let tile_height = full_height.div_ceil(NEAR_TILE_SIZE).max(1);
        Ok(Self {
            full_width,
            full_height,
            half_width,
            half_height,
            half_inv_width: 1.0 / half_width as f32,
            half_inv_height: 1.0 / half_height as f32,
            scalar_format,
            full_coc: EffectTarget::create(device, full_width, full_height, scalar_format)?,
            prefilter: EffectTarget::create(device, half_width, half_height, D3DFMT_A16B16G16R16F)?,
            far: EffectTarget::create(device, half_width, half_height, D3DFMT_A16B16G16R16F)?,
            near: EffectTarget::create(device, half_width, half_height, D3DFMT_A16B16G16R16F)?,
            near_tile_rows: SizedTarget::create(device, tile_width, full_height, scalar_format)?,
            near_tile: SizedTarget::create(device, tile_width, tile_height, scalar_format)?,
            near_tile_temp: SizedTarget::create(device, tile_width, tile_height, scalar_format)?,
            near_tile_expanded: SizedTarget::create(
                device,
                tile_width,
                tile_height,
                scalar_format,
            )?,
            near_coc: EffectTarget::create(device, half_width, half_height, scalar_format)?,
            focus_a: EffectTarget::create(device, 1, 1, scalar_format)?,
            focus_b: EffectTarget::create(device, 1, 1, scalar_format)?,
            quarter: SizedTarget::create(
                device,
                full_width.div_ceil(QUARTER_SCALE).max(1),
                full_height.div_ceil(QUARTER_SCALE).max(1),
                D3DFMT_A16B16G16R16F,
            )?,
            eighth: SizedTarget::create(
                device,
                full_width.div_ceil(EIGHTH_SCALE).max(1),
                full_height.div_ceil(EIGHTH_SCALE).max(1),
                D3DFMT_A16B16G16R16F,
            )?,
        })
    }

    fn matches(&self, width: u32, height: u32, scalar_format: D3DFORMAT) -> bool {
        self.full_width == width
            && self.full_height == height
            && self.scalar_format == scalar_format
    }

    fn focus_pair(&self, current_is_a: bool) -> (&Texture9, &EffectTarget) {
        if current_is_a {
            (&self.focus_a.texture, &self.focus_b)
        } else {
            (&self.focus_b.texture, &self.focus_a)
        }
    }

    fn current_focus(&self, current_is_a: bool) -> &Texture9 {
        if current_is_a {
            &self.focus_a.texture
        } else {
            &self.focus_b.texture
        }
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

struct SizedTarget {
    width: u32,
    height: u32,
    inv_width: f32,
    inv_height: f32,
    texture: Texture9,
    surface: Surface9,
}

impl SizedTarget {
    fn create(
        device: &Device9Ref<'_>,
        width: u32,
        height: u32,
        format: D3DFORMAT,
    ) -> Direct3DResult<Self> {
        let target = EffectTarget::create(device, width, height, format)?;
        Ok(Self {
            width,
            height,
            inv_width: 1.0 / width as f32,
            inv_height: 1.0 / height as f32,
            texture: target.texture,
            surface: target.surface,
        })
    }
}

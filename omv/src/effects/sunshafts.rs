//! Engine-side sunshafts pipeline.
//!
//! Immutable HLSL bytecode is prepared by a background worker. Render
//! callbacks create only D3D objects and never invoke the compiler or cache.
//! The native directional sun snapshot admits rays independently of its sprite.
//! World/first-person depth supplies per-tap openness; unavailable required
//! inputs skip output. Device-owned intermediates reset with the device. Five
//! bounded passes retain half-resolution marching and filtering. The radial
//! field carries fractional missing illumination; coverage-guided reconstruction
//! preserves narrow silhouettes/openings. Offscreen forward rays sample only
//! the known viewport. Composition weights sky/fog occlusion by haze opacity
//! in scene-post color. This stylized occlusion is separate from physical
//! volumetric in-scattering and never adds an open-sky halo.

use std::{
    sync::{
        LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use anyhow::Result;
use libpsycho::os::windows::directx9::{
    D3DCULL_NONE, D3DFORMAT, D3DRS_ADAPTIVETESS_Y, D3DRS_ALPHABLENDENABLE, D3DRS_ALPHATESTENABLE,
    D3DRS_COLORWRITEENABLE, D3DRS_CULLMODE, D3DRS_MULTISAMPLEMASK, D3DRS_POINTSIZE,
    D3DRS_SCISSORTESTENABLE, D3DRS_SRGBWRITEENABLE, D3DRS_STENCILENABLE, D3DRS_ZENABLE,
    D3DRS_ZWRITEENABLE, D3DSAMP_ADDRESSU, D3DSAMP_ADDRESSV, D3DSAMP_MAGFILTER, D3DSAMP_MINFILTER,
    D3DSAMP_MIPFILTER, D3DSAMP_SRGBTEXTURE, D3DSURFACE_DESC, D3DTA_TEXTURE, D3DTADDRESS_CLAMP,
    D3DTEXF_LINEAR, D3DTEXF_NONE, D3DTEXF_POINT, D3DTOP_SELECTARG1, D3DTSS_ALPHAARG1,
    D3DTSS_ALPHAOP, D3DTSS_COLORARG1, D3DTSS_COLOROP, D3DVIEWPORT9, Device9Ref, Direct3DResult,
    PixelShader9, ScreenVertex, Surface9, Texture9, direct3d_failure,
};

use crate::{
    backend::{DepthTexture, FrameInputs, NativeSkyFrame, SunProjectionFrame},
    shaders::{self, ScreenShaderSource},
};
use parking_lot::Mutex;

const COLOR_WRITE_ALL: u32 = 0x0F;
const AMD_ALPHA_TO_COVERAGE_OFF: u32 = u32::from_le_bytes(*b"A2M0");
const EFFECT_CONSTANT_REGISTER: u32 = 9;
const MASK_SCALE: u32 = 2;

const MASK_SHADER: &[u8] = include_bytes!("../../shaders/embedded/sunshafts_mask.hlsl");
const RADIAL_SHADER: &[u8] = include_bytes!("../../shaders/embedded/sunshafts_radial.hlsl");
const BLUR_SHADER: &[u8] = include_bytes!("../../shaders/embedded/sunshafts_blur.hlsl");
const COMPOSE_SHADER: &[u8] = include_bytes!("../../shaders/embedded/sunshafts_compose.hlsl");

static COMPILE_STARTED: AtomicBool = AtomicBool::new(false);
static COMPILE_FAILED: AtomicBool = AtomicBool::new(false);
static COMPILE_READY: AtomicBool = AtomicBool::new(false);
static BYTECODE: LazyLock<Mutex<Option<SunshaftsBytecode>>> = LazyLock::new(|| Mutex::new(None));

struct SunshaftsBytecode {
    mask: Vec<u32>,
    radial: Vec<u32>,
    blur: Vec<u32>,
    compose: Vec<u32>,
}

impl SunshaftsBytecode {
    fn compile() -> Result<Self> {
        Ok(Self {
            mask: shaders::compile_hlsl_source("sunshafts_mask.hlsl", MASK_SHADER)?,
            radial: shaders::compile_hlsl_source("sunshafts_radial.hlsl", RADIAL_SHADER)?,
            blur: shaders::compile_hlsl_source("sunshafts_blur.hlsl", BLUR_SHADER)?,
            compose: shaders::compile_hlsl_source("sunshafts_compose.hlsl", COMPOSE_SHADER)?,
        })
    }
}

/// Start process-owned sunshaft shader preparation outside render callbacks.
pub(crate) fn service_preparation() {
    if COMPILE_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    if let Err(err) = thread::Builder::new()
        .name("omv-sunshafts-compile".to_owned())
        .spawn(
            || match super::shader_preparation::run_serialized(SunshaftsBytecode::compile) {
                Ok(bytecode) => {
                    *BYTECODE.lock() = Some(bytecode);
                    COMPILE_READY.store(true, Ordering::Release);
                }
                Err(err) => {
                    COMPILE_FAILED.store(true, Ordering::Release);
                    log::warn!("[SUNSHAFTS] Shader preparation failed: {err:#}");
                }
            },
        )
    {
        COMPILE_FAILED.store(true, Ordering::Release);
        log::warn!("[SUNSHAFTS] Could not start shader preparation: {err}");
    }
}

/// Return whether sunshaft bytecode is ready for device-object creation.
pub(crate) fn preparation_ready() -> bool {
    COMPILE_READY.load(Ordering::Acquire) && !COMPILE_FAILED.load(Ordering::Acquire)
}

#[derive(Clone, Copy)]
struct NativeSunshaftFrame {
    projection: SunProjectionFrame,
    sky: NativeSkyFrame,
}

fn resolve_native_sun(frame_inputs: &FrameInputs) -> Option<NativeSunshaftFrame> {
    let sky = frame_inputs.sky?;
    if !sky.is_exterior || !sky.daylight.is_finite() || sky.daylight <= 0.001 {
        return None;
    }
    let mut projection =
        crate::backend::project_world_direction(frame_inputs.camera, sky.sun_direction);
    // Viewport admission hides overhead rays. Fade only at the projection
    // singularity; HLSL clips the radial path to available depth coverage.
    let facing = (projection.facing / 0.12).clamp(0.0, 1.0);
    projection.edge_fade = facing * facing * (3.0 - 2.0 * facing);
    (projection.facing > 0.001
        && projection.edge_fade > 0.0
        && sky.resolved_exterior_sun_color().is_some())
    .then_some(NativeSunshaftFrame { projection, sky })
}

fn first_person_occlusion_requested(source: &ScreenShaderSource) -> bool {
    source
        .option_constants
        .get(2)
        .is_some_and(|value| value[0].is_finite() && value[0] > 0.001)
}

/// Admit only frames with required depth, viable sunlight and a nonzero
/// compose footprint. Pure packet inspection; no D3D allocation or engine read.
pub(crate) fn should_draw(frame_inputs: &FrameInputs, source: &ScreenShaderSource) -> bool {
    let Some(sun) = resolve_native_sun(frame_inputs) else {
        return false;
    };
    let (Some(amount), Some(force), Some(receiver)) = (
        source.option_constants.first(),
        source.option_constants.get(1),
        source.option_constants.get(2),
    ) else {
        return false;
    };
    // These are the compose pass's exact neutral-output conditions. Reject
    // them before targets, source copies or any of the five passes.
    if ![amount[0], amount[1], force[0], receiver[1]]
        .into_iter()
        .all(f32::is_finite)
        || amount[0] <= 0.0
        || amount[1] <= 0.0
        || force[0] <= 0.0
    {
        return false;
    }
    if receiver[3] <= 0.5 {
        // Offscreen suns are admitted only where the existing receiver radius
        // reaches the viewport. Unknown depth never becomes an opaque blocker.
        let aspect = frame_inputs.camera.aspect_ratio;
        if !aspect.is_finite() {
            return false;
        }
        let uv = sun.projection.uv;
        let x = (uv[0] - uv[0].clamp(0.0, 1.0)) * aspect.max(0.1);
        let y = uv[1] - uv[1].clamp(0.0, 1.0);
        if (x * x + y * y).sqrt() >= receiver[1].max(0.08) {
            return false;
        }
    }
    frame_inputs.depth.texture.is_some()
        && (!frame_inputs.material_state.exterior_known || frame_inputs.material_state.is_exterior)
        && (!first_person_occlusion_requested(source) || first_person_occlusion_safe(frame_inputs))
}

fn first_person_contract_ready(frame_inputs: &FrameInputs) -> bool {
    frame_inputs.depth.first_person_texture.is_some()
}

fn first_person_occlusion_safe(frame_inputs: &FrameInputs) -> bool {
    !frame_inputs.first_person_rendered || first_person_contract_ready(frame_inputs)
}

#[cfg(test)]
mod shader_compile_tests {
    use core::ffi::c_void;

    use super::{
        BLUR_SHADER, COMPOSE_SHADER, MASK_SHADER, RADIAL_SHADER, first_person_contract_ready,
        first_person_occlusion_safe,
    };
    use crate::backend::{DepthTexture, FrameInputs};

    #[test]
    fn embedded_sunshaft_shaders_compile() {
        for (name, source, instructions, textures, bytes) in [
            ("sunshafts_mask.hlsl", MASK_SHADER, 191, 8, 3292),
            ("sunshafts_radial.hlsl", RADIAL_SHADER, 196, 1, 3228),
            ("sunshafts_blur.hlsl", BLUR_SHADER, 174, 15, 2812),
            ("sunshafts_compose.hlsl", COMPOSE_SHADER, 358, 5, 5944),
        ] {
            crate::shaders::assert_pixel_shader_budget(name, source, instructions, textures, bytes);
        }
    }

    #[test]
    fn first_person_mask_requires_its_texture_not_unconsumed_projection_fields() {
        let mut inputs = FrameInputs::default();
        assert!(!first_person_contract_ready(&inputs));
        assert!(first_person_occlusion_safe(&inputs));

        inputs.first_person_rendered = true;
        assert!(!first_person_occlusion_safe(&inputs));
        inputs.depth.first_person_texture = DepthTexture::new(1usize as *mut c_void);
        assert!(first_person_contract_ready(&inputs));
        assert!(first_person_occlusion_safe(&inputs));
        assert!(!inputs.depth.first_person_projection.camera.available);
        assert!(
            inputs
                .depth
                .first_person_projection
                .reversed_depth
                .is_none()
        );
    }

    #[test]
    fn sunshaft_vendor_coverage_disable_magic_is_exact() {
        assert_eq!(super::AMD_ALPHA_TO_COVERAGE_OFF, 0x304D_3241);
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
    /// Create device-owned sunshaft resources from prepared bytecode.
    ///
    /// `Ok(None)` is a normal nonblocking result while preparation is active.
    pub(crate) fn create(device: &Device9Ref<'_>) -> Direct3DResult<Option<Self>> {
        service_preparation();
        if COMPILE_FAILED.load(Ordering::Acquire) {
            return Err(direct3d_failure());
        }
        if !COMPILE_READY.load(Ordering::Acquire) {
            return Ok(None);
        }
        let Some(bytecode) = BYTECODE.try_lock() else {
            return Ok(None);
        };
        let Some(bytecode) = bytecode.as_ref() else {
            return Ok(None);
        };
        Self::create_from_bytecode(device, bytecode).map(Some)
    }

    fn create_from_bytecode(
        device: &Device9Ref<'_>,
        bytecode: &SunshaftsBytecode,
    ) -> Direct3DResult<Self> {
        Ok(Self {
            mask_shader: device.create_pixel_shader(&bytecode.mask)?,
            radial_shader: device.create_pixel_shader(&bytecode.radial)?,
            blur_shader: device.create_pixel_shader(&bytecode.blur)?,
            compose_shader: device.create_pixel_shader(&bytecode.compose)?,
            targets: None,
        })
    }

    /// Execute the production passes with a retained, validated source packet.
    /// The runtime resolves native input before resource creation. Returns true
    /// only after writing output; unavailable frame input returns false. D3D
    /// failures propagate to the caller's state-restoration/color-graph boundary.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn draw(
        &mut self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &FrameInputs,
        source: &ScreenShaderSource,
        scene_color: &Texture9,
        frame_index: u32,
    ) -> Direct3DResult<bool> {
        if !should_draw(frame_inputs, source) {
            return Ok(false);
        }

        self.ensure_targets(device, desc)?;
        let Some(targets) = self.targets.as_ref() else {
            return Ok(false);
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
        )?;
        Ok(true)
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
        device.set_texture(3, &targets.mask.texture)?;
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

fn bind_pipeline_state(device: &Device9Ref<'_>) -> Direct3DResult<()> {
    // Scene-post input/output already use the established image-space encoding.
    device.set_render_state(D3DRS_SRGBWRITEENABLE, 0)?;
    device.set_render_state(D3DRS_SCISSORTESTENABLE, 0)?;
    device.set_render_state(D3DRS_STENCILENABLE, 0)?;
    device.set_render_state(D3DRS_MULTISAMPLEMASK, u32::MAX)?;
    device.clear_vertex_shader()?;
    device.set_fvf(ScreenVertex::FVF)?;
    device.set_render_state(D3DRS_CULLMODE, D3DCULL_NONE.0 as u32)?;
    device.set_render_state(D3DRS_ALPHABLENDENABLE, 0)?;
    device.set_render_state(D3DRS_ALPHATESTENABLE, 0)?;
    device.set_render_state(D3DRS_ZENABLE, 0)?;
    device.set_render_state(D3DRS_ZWRITEENABLE, 0)?;
    device.set_render_state(D3DRS_COLORWRITEENABLE, COLOR_WRITE_ALL)?;
    match crate::backend::fnv_alpha_coverage_mode() {
        crate::backend::AlphaCoverageMode::None => {}
        crate::backend::AlphaCoverageMode::Nvidia => {
            device.set_render_state(D3DRS_ADAPTIVETESS_Y, 0)?;
        }
        crate::backend::AlphaCoverageMode::Amd => {
            device.set_render_state(D3DRS_POINTSIZE, AMD_ALPHA_TO_COVERAGE_OFF)?;
        }
    }
    for sampler in [0, 1, 2, 3, 4] {
        device.set_sampler_state(sampler, D3DSAMP_SRGBTEXTURE, 0)?;
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

    crate::render_state::clear_sampler(device, 0)?;
    crate::render_state::clear_sampler(device, 3)?;
    crate::render_state::clear_sampler(device, 4)?;
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
        crate::render_state::clear_sampler(device, 1)?;
    }

    if let Some(depth) = first_person_depth {
        unsafe {
            device.set_raw_base_texture(2, depth.as_ptr())?;
        }
    } else {
        crate::render_state::clear_sampler(device, 2)?;
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
    let Some(sun) = resolve_native_sun(frame_inputs) else {
        return Err(direct3d_failure());
    };
    let Some(sun_color) = sun.sky.resolved_exterior_sun_color() else {
        return Err(direct3d_failure());
    };
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
            sun.projection.uv[0],
            sun.projection.uv[1],
            1.0,
            // Shared sun color already owns daylight; visibility owns only projection.
            sun.projection.edge_fade,
        ]],
    )?;
    device.set_pixel_shader_constant_f(
        10,
        &[[
            sun_color[0],
            sun_color[1],
            sun_color[2],
            sun.projection.edge_fade,
        ]],
    )?;
    device.set_pixel_shader_constant_f(
        15,
        &[[
            // The publisher already converted transmittance to opacity.
            frame_inputs.atmosphere_visibility.clamp(0.0, 1.0),
            frame_inputs.atmosphere_available as u8 as f32,
            0.0,
            0.0,
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
    let first_person_ready = first_person_contract_ready(frame_inputs);
    device.set_pixel_shader_constant_f(
        11,
        &[
            [
                world.reversed_depth_f32(),
                first_person.reversed_depth_f32(),
                frame_inputs.first_person_rendered as u8 as f32,
                first_person_ready as u8 as f32,
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
    unsafe { crate::render_state::draw_fullscreen_quad(device, &quad) }
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

#[cfg(test)]
mod shader_behavior {
    //! End-to-end D3D9 behavior gate for the independent legacy godray pass.
    //!
    //! The test compiles and executes every shipped sunshaft pass and accepts
    //! only final production-format pixels. This catches an empty source mask,
    //! a broken radial path, lost occluders, or bright edge accents replacing
    //! shadow bands. A nonblack receiver is required to observe attenuation.

    use super::{SunshaftsBytecode, SunshaftsEffect};
    use crate::{
        backend::{
            CameraFrame, CameraTransformFrame, DepthFrame, DepthProjectionFrame, DepthProvider,
            DepthTexture, EnvironmentFrame, FrameInputs, MaterialStateFrame, NativeSkyFrame,
            SunFrame,
        },
        config::EmbeddedEffectsConfig,
        shaders::{EmbeddedEffectKind, merge_embedded_sources},
    };
    use libpsycho::os::windows::{
        directx9::{
            D3DCLEAR_TARGET, D3DDEVTYPE_HAL, D3DDEVTYPE_NULLREF, D3DFMT_A8R8G8B8, D3DFMT_X8R8G8B8,
            D3DPOOL_MANAGED, Device9, Device9Ref, Texture9, create_direct3d9,
        },
        winapi::{get_active_window, get_desktop_window, get_foreground_window},
    };

    const TEST_SIZE: u32 = 64;
    const FRAME_EPOCH: u64 = 23;

    fn raster_device() -> Device9 {
        let window = [
            get_active_window(),
            get_foreground_window(),
            get_desktop_window().unwrap_or(std::ptr::null_mut()),
        ]
        .into_iter()
        .find(|window| !window.is_null())
        .expect("Wine must expose a window for sunshaft shader validation");
        let direct3d = create_direct3d9().expect("D3D9 runtime");
        direct3d
            .create_windowed_device(window, TEST_SIZE, TEST_SIZE, D3DDEVTYPE_HAL)
            .or_else(|_| {
                direct3d.create_windowed_device(window, TEST_SIZE, TEST_SIZE, D3DDEVTYPE_NULLREF)
            })
            .expect("HAL or NULLREF D3D9 device")
    }

    fn source() -> crate::shaders::ScreenShaderSource {
        merge_embedded_sources(&EmbeddedEffectsConfig::default(), Vec::new())
            .into_iter()
            .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::Sunshafts))
            .expect("default sunshaft source")
    }

    fn camera() -> CameraFrame {
        CameraFrame {
            near_z: 5.0,
            far_z: 200_000.0,
            aspect_ratio: 1.0,
            frustum_left: -1.0,
            frustum_right: 1.0,
            frustum_bottom: -1.0,
            frustum_top: 1.0,
            world_transform: CameraTransformFrame {
                available: true,
                ..CameraTransformFrame::default()
            },
            available: true,
        }
    }

    fn raw_depth(device: &Device9Ref<'_>, blocker: bool) -> Texture9 {
        let depth = device
            .create_texture(TEST_SIZE, TEST_SIZE, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)
            .expect("lockable raw-depth texture");
        let mut pixels = vec![0xFF00_0000u32; (TEST_SIZE * TEST_SIZE) as usize];
        if blocker {
            for y in 25..39usize {
                for x in 29..35usize {
                    pixels[y * TEST_SIZE as usize + x] = 0xFF40_0000;
                }
            }
        }
        depth
            .write_level0_argb(TEST_SIZE, TEST_SIZE, &pixels)
            .expect("raw-depth pixels");
        depth
    }

    fn frame(depth: &Texture9, sun_direction: [f32; 3]) -> FrameInputs {
        let camera = camera();
        let projection = DepthProjectionFrame {
            camera,
            reversed_depth: Some(true),
            depth_function: Some(7),
            source_surface: depth.as_raw_base_texture() as usize,
            sampled_depth_bits: 24,
            image: Default::default(),
        };
        FrameInputs {
            camera,
            depth: DepthFrame::from_textures(
                DepthProvider::FalloutNewVegas,
                DepthTexture::new(depth.as_raw_base_texture()),
                None,
                projection,
                DepthProjectionFrame::default(),
                FRAME_EPOCH,
            ),
            environment: EnvironmentFrame {
                fog_start: 1_000.0,
                fog_end: 120_000.0,
                fog_power: 0.5,
                fog_available: true,
                ..EnvironmentFrame::default()
            },
            sun: SunFrame {
                screen_x: 0.5,
                screen_y: 0.5,
                available: true,
                daylight: 0.4252,
            },
            sky: Some(NativeSkyFrame {
                sky_upper: [0.2, 0.3, 0.6],
                sky_lower: [0.4, 0.45, 0.55],
                horizon: [0.65, 0.6, 0.5],
                // FNV can leave the Reloaded-derived sky color candidates
                // black even though the native exterior/daylight contract is
                // valid. The shipped effect must not disappear in that frame.
                sun_light: [0.0; 3],
                sun_disk: [0.0; 3],
                sun_direction,
                daylight: 0.4252,
                game_hour: 18.0,
                is_exterior: true,
                reversed_depth: true,
            }),
            atmosphere_visibility: 0.6,
            atmosphere_available: true,
            first_person_rendered: false,
            third_person_view: Some(true),
            material_state: MaterialStateFrame {
                exterior_known: true,
                is_exterior: true,
            },
        }
    }

    fn clear_target(device: &Device9Ref<'_>, texture: &Texture9, color: u32) {
        let surface = texture.surface_level(0).expect("HDR surface");
        device.set_render_target(0, &surface).expect("HDR target");
        device
            .clear_attachments(D3DCLEAR_TARGET as u32, color, 1.0, 0)
            .expect("clear HDR target");
    }

    fn render(
        effect: &mut SunshaftsEffect,
        device: &Device9Ref<'_>,
        scene_color: &Texture9,
        source: &crate::shaders::ScreenShaderSource,
        sun_direction: [f32; 3],
        blocker: bool,
    ) -> Vec<[f32; 4]> {
        let depth = raw_depth(device, blocker);
        render_inputs(
            effect,
            device,
            scene_color,
            source,
            &frame(&depth, sun_direction),
        )
    }

    fn render_inputs(
        effect: &mut SunshaftsEffect,
        device: &Device9Ref<'_>,
        scene_color: &Texture9,
        source: &crate::shaders::ScreenShaderSource,
        inputs: &FrameInputs,
    ) -> Vec<[f32; 4]> {
        let output = device
            .create_render_target_texture(TEST_SIZE, TEST_SIZE, D3DFMT_X8R8G8B8)
            .expect("production-format sunshaft output");
        clear_target(device, &output, 0);
        let output_surface = output
            .surface_level(0)
            .expect("production-format output surface");
        let desc = output_surface
            .desc()
            .expect("production-format output description");
        device.begin_scene().expect("begin sunshaft behavior draw");
        effect
            .draw(
                device,
                &output_surface,
                &desc,
                inputs,
                source,
                scene_color,
                31,
            )
            .expect("complete sunshaft behavior draw");
        device.end_scene().expect("end sunshaft behavior draw");
        let staging = device
            .create_system_memory_surface(TEST_SIZE, TEST_SIZE, D3DFMT_X8R8G8B8)
            .expect("production-format readback surface");
        device
            .copy_render_target_data(&output_surface, &staging)
            .expect("production-format sunshaft readback");
        staging
            .read_rgba8()
            .expect("production-format sunshaft pixels")
    }

    fn luminance(pixel: [f32; 4]) -> f32 {
        pixel[0] * 0.2126 + pixel[1] * 0.7152 + pixel[2] * 0.0722
    }

    #[test]
    fn shadow_wedge_remains_visible_away_from_the_emitter() {
        // The supplied Borderlands references establish a continuous shadow
        // wedge through haze. This existing production depth fixture tests
        // that requirement; it is not a reconstruction of their engine data.
        let owner = raster_device();
        let device = owner.as_ref();
        let code = SunshaftsBytecode::compile().unwrap();
        let mut effect = SunshaftsEffect::create_from_bytecode(&device, &code).unwrap();
        let source = source();
        let scene = device
            .create_render_target_texture(TEST_SIZE, TEST_SIZE, D3DFMT_X8R8G8B8)
            .unwrap();
        clear_target(&device, &scene, 0xFF80_8080);
        let world = raw_depth(&device, false);
        let weapon = raw_depth(&device, true);
        let mut inputs = frame(&world, [1.0, 0.75, 0.0]);
        let projection = crate::backend::project_world_direction(inputs.camera, [1.0, 0.75, 0.0]);
        assert_eq!(projection.uv, [0.5, 0.125]);
        let open = render_inputs(&mut effect, &device, &scene, &source, &inputs);
        inputs.first_person_rendered = true;
        inputs.depth.first_person_texture = DepthTexture::new(weapon.as_raw_base_texture());
        let shadow = render_inputs(&mut effect, &device, &scene, &source, &inputs);
        for (index, (a, b)) in open.iter().zip(&shadow).enumerate() {
            let contrast = luminance(*a) - luminance(*b);
            assert!(b.iter().all(|v| v.is_finite()));
            assert!(contrast >= -1.0 / 255.0, "shadow wedge added highlights");
            assert!(
                (luminance(*a) - 128.0 / 255.0).abs() <= 1.0 / 255.0,
                "unoccluded sky changed"
            );
            let x = index % TEST_SIZE as usize;
            let y = index / TEST_SIZE as usize;
            if (29..35).contains(&x) && (25..39).contains(&y) {
                assert!(contrast.abs() <= 1.0 / 255.0, "weapon receiver changed");
            }
            if (31..33).contains(&x) && (43..55).contains(&y) {
                assert!(
                    contrast >= 0.10 * (128.0 / 255.0),
                    "projected shadow faded into invisibility: ({x}, {y}), contrast={contrast}"
                );
            }
            if x == 4 || x == 59 {
                assert!(
                    contrast.abs() <= 1.0 / 255.0,
                    "shadow escaped its silhouette wedge: ({x}, {y})"
                );
            }
        }
    }

    #[test]
    fn production_haze_opacity_strengthens_visible_bands() {
        use crate::backend::AtmosphereFrame;
        use crate::effects::atmosphere::AtmosphereSettings;
        let owner = raster_device();
        let device = owner.as_ref();
        let code = SunshaftsBytecode::compile().unwrap();
        let mut effect = SunshaftsEffect::create_from_bytecode(&device, &code).unwrap();
        let source = source();
        let scene = device
            .create_render_target_texture(TEST_SIZE, TEST_SIZE, D3DFMT_X8R8G8B8)
            .unwrap();
        clear_target(&device, &scene, 0xFF80_8080);
        let world = raw_depth(&device, false);
        let weapon = raw_depth(&device, true);
        let mut inputs = frame(&world, [1.0, 0.0, 0.0]);
        let defaults = EmbeddedEffectsConfig::default();
        let mut peaks = Vec::new();
        for density in [
            defaults.volumetric_lighting.medium_density,
            defaults.volumetric_lighting.medium_density * 2.0,
        ] {
            let mut lighting = defaults.volumetric_lighting;
            lighting.medium_density = density;
            let settings = AtmosphereSettings::from_config(defaults.volumetric_fog, lighting);
            let atmosphere = AtmosphereFrame {
                camera: inputs.camera,
                depth: inputs.depth,
                environment: inputs.environment,
                underwater: Default::default(),
                sun: inputs.sun,
                sky: inputs.sky,
                material_state: inputs.material_state,
                frame_epoch: FRAME_EPOCH,
                distance_bound: settings.max_distance,
            };
            // Use the same production estimate and opacity conversion as the
            // world publisher, rather than a fixed fixture transmittance.
            inputs.atmosphere_visibility =
                1.0 - settings.estimated_horizontal_transmittance(atmosphere);
            inputs.first_person_rendered = false;
            inputs.depth.first_person_texture = None;
            let open = render_inputs(&mut effect, &device, &scene, &source, &inputs);
            inputs.first_person_rendered = true;
            inputs.depth.first_person_texture = DepthTexture::new(weapon.as_raw_base_texture());
            let shadow = render_inputs(&mut effect, &device, &scene, &source, &inputs);
            let mut peak = 0.0f32;
            let mut broad = 0usize;
            for (index, (a, b)) in open.iter().zip(&shadow).enumerate() {
                let contrast = luminance(*a) - luminance(*b);
                let x = index % TEST_SIZE as usize;
                let y = index / TEST_SIZE as usize;
                assert!(b.iter().all(|v| v.is_finite()));
                assert!(contrast >= -1.0 / 255.0, "rays added light");
                if (29..35).contains(&x) && (25..39).contains(&y) {
                    assert!(contrast.abs() <= 1.0 / 255.0, "weapon receiver changed");
                } else {
                    peak = peak.max(contrast);
                }
                // Existing broad-darkening criterion also defines a band
                // with substantive contrast, instead of only two LDR codes.
                broad += usize::from(contrast >= 0.10 * (128.0 / 255.0));
            }
            assert!(broad < open.len() / 4, "bands became full-screen darkening");
            peaks.push(peak);
        }
        assert!(
            peaks[1] > peaks[0],
            "denser production haze weakened bands: {peaks:?}"
        );
        assert!(
            peaks[0] >= 0.10 * (128.0 / 255.0),
            "default bands lack substantive contrast: {peaks:?}"
        );
    }

    #[test]
    fn first_person_blocker_casts_bounded_rays_without_shading_the_weapon() {
        let owner = raster_device();
        let device = owner.as_ref();
        let bytecode = SunshaftsBytecode::compile().unwrap();
        let mut effect = SunshaftsEffect::create_from_bytecode(&device, &bytecode).unwrap();
        let source = source();
        let scene = device
            .create_render_target_texture(TEST_SIZE, TEST_SIZE, D3DFMT_X8R8G8B8)
            .unwrap();
        clear_target(&device, &scene, 0xFF80_8080);
        let world = raw_depth(&device, false);
        let weapon = raw_depth(&device, true);
        let mut inputs = frame(&world, [1.0, 0.0, 0.0]);
        let open = render_inputs(&mut effect, &device, &scene, &source, &inputs);
        inputs.first_person_rendered = true;
        inputs.depth.first_person_texture = DepthTexture::new(weapon.as_raw_base_texture());
        let blocked = render_inputs(&mut effect, &device, &scene, &source, &inputs);
        let mut peak = 0.0f32;
        let mut broad = 0usize;
        for (index, (a, b)) in open.iter().zip(&blocked).enumerate() {
            let x = index % TEST_SIZE as usize;
            let y = index / TEST_SIZE as usize;
            let contrast = luminance(*a) - luminance(*b);
            if (29..35).contains(&x) && (25..39).contains(&y) {
                assert!(contrast.abs() <= 1.0 / 255.0, "weapon receiver changed");
            } else {
                peak = peak.max(contrast);
            }
            broad += usize::from(contrast > 0.10 * 128.0 / 255.0);
        }
        assert!(peak >= 2.0 / 255.0, "weapon cast no visible shadow bands");
        assert!(
            broad < open.len() / 4,
            "weapon darkened a broad region: {broad}"
        );
        inputs.depth.first_person_texture = None;
        assert!(
            !super::should_draw(&inputs, &source),
            "missing weapon depth must fail closed"
        );
    }

    #[test]
    fn one_pixel_opening_preserves_fractional_mask_coverage() {
        let owner = raster_device();
        let device = owner.as_ref();
        let code = SunshaftsBytecode::compile().unwrap();
        let mut effect = SunshaftsEffect::create_from_bytecode(&device, &code).unwrap();
        let depth = device
            .create_texture(TEST_SIZE, TEST_SIZE, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)
            .unwrap();
        for reversed in [true, false] {
            let mut pixels = vec![0xFF40_0000; (TEST_SIZE * TEST_SIZE) as usize];
            for y in 0..TEST_SIZE as usize {
                pixels[y * TEST_SIZE as usize + 32] =
                    if reversed { 0xFF00_0000 } else { 0xFFFF_0000 };
            }
            depth
                .write_level0_argb(TEST_SIZE, TEST_SIZE, &pixels)
                .unwrap();
            let scene = device
                .create_render_target_texture(TEST_SIZE, TEST_SIZE, D3DFMT_X8R8G8B8)
                .unwrap();
            clear_target(&device, &scene, 0xFF80_8080);
            let desc = scene.surface_level(0).unwrap().desc().unwrap();
            effect.ensure_targets(&device, &desc).unwrap();
            let targets = effect.targets.as_ref().unwrap();
            device.begin_scene().unwrap();
            super::bind_pipeline_state(&device).unwrap();
            let mut frame = frame(&depth, [1.0, 0.0, 0.0]);
            frame.depth.world_projection.reversed_depth = Some(reversed);
            super::bind_depth_inputs(
                &device,
                &frame.depth.texture,
                &frame.depth.first_person_texture,
            )
            .unwrap();
            effect
                .draw_mask(&device, targets, &desc, &frame, &source(), &scene, 0)
                .unwrap();
            device.end_scene().unwrap();
            let staging = device
                .create_system_memory_surface(targets.width, targets.height, D3DFMT_X8R8G8B8)
                .unwrap();
            device
                .copy_render_target_data(&targets.mask.surface, &staging)
                .unwrap();
            let values = staging.read_rgba8().unwrap();
            let coverage = values[(targets.height / 2 * targets.width + 16) as usize][1];
            assert!(
                (coverage - 0.5).abs() <= 1.0 / 255.0,
                "one of two full-resolution columns must yield half coverage: {coverage}"
            );
        }
    }

    #[test]
    fn offscreen_forward_sun_retains_admission() {
        let owner = raster_device();
        let device = owner.as_ref();
        let depth = raw_depth(&device, false);
        let source = source();
        assert!(super::should_draw(
            &frame(&depth, [1.0, 1.02, 0.0]),
            &source
        ));
        assert!(!super::should_draw(
            &frame(&depth, [1.0, 5.0, 0.0]),
            &source
        ));
        for (group, component) in [(0, 0), (0, 1), (1, 0)] {
            let mut neutral = source.clone();
            neutral.option_constants[group][component] = 0.0;
            assert!(!super::should_draw(
                &frame(&depth, [1.0, 0.0, 0.0]),
                &neutral
            ));
        }
    }

    #[test]
    fn rays_remain_continuous_across_the_top_viewport_edge() {
        let owner = raster_device();
        let device = owner.as_ref();
        let code = SunshaftsBytecode::compile().unwrap();
        let mut effect = SunshaftsEffect::create_from_bytecode(&device, &code).unwrap();
        let source = source();
        let scene = device
            .create_render_target_texture(TEST_SIZE, TEST_SIZE, D3DFMT_X8R8G8B8)
            .unwrap();
        clear_target(&device, &scene, 0xFF80_8080);
        let mut energies = Vec::new();
        for y in [0.98, 1.0, 1.02] {
            let open = render(&mut effect, &device, &scene, &source, [1.0, y, 0.0], false);
            assert!(
                open.iter()
                    .all(|p| (luminance(*p) - 128.0 / 255.0).abs() <= 1.0 / 255.0),
                "unknown offscreen depth must not create shadows"
            );
            let shadow = render(&mut effect, &device, &scene, &source, [1.0, y, 0.0], true);
            energies.push(
                open.iter()
                    .zip(&shadow)
                    .map(|(a, b)| (luminance(*a) - luminance(*b)).max(0.0))
                    .sum::<f32>(),
            );
        }
        let minimum = energies.iter().copied().fold(f32::INFINITY, f32::min);
        let maximum = energies.iter().copied().fold(0.0f32, f32::max);
        assert!(
            minimum > 0.0 && minimum >= maximum * 0.5,
            "ray energy collapsed at the viewport edge: {energies:?}"
        );
    }

    #[test]
    fn narrow_blocker_does_not_blacken_the_sky_and_offscreen_sun_keeps_rays() {
        let owner = raster_device();
        let device = owner.as_ref();
        let bytecode = SunshaftsBytecode::compile().unwrap();
        let mut effect = SunshaftsEffect::create_from_bytecode(&device, &bytecode).unwrap();
        let source = source();
        let scene = device
            .create_render_target_texture(TEST_SIZE, TEST_SIZE, D3DFMT_X8R8G8B8)
            .unwrap();
        clear_target(&device, &scene, 0xFF80_8080);
        for sun in [[1.0, 0.0, 0.0], [1.0, 1.02, 0.0]] {
            let depth = raw_depth(&device, false);
            assert!(
                super::should_draw(&frame(&depth, sun), &source),
                "forward sun outside the viewport must retain ray admission: {sun:?}"
            );
            let open = render(&mut effect, &device, &scene, &source, sun, false);
            let blocked = render(&mut effect, &device, &scene, &source, sun, true);
            let mut strongest = 0.0f32;
            let mut darkened = 0usize;
            for (a, b) in open.iter().zip(&blocked) {
                let contrast = luminance(*a) - luminance(*b);
                strongest = strongest.max(contrast);
                darkened += usize::from(contrast > 0.10 * (128.0 / 255.0));
                assert!(b.iter().all(|v| v.is_finite()));
                assert!(contrast >= -1.0 / 255.0, "shadow rays must not add a halo");
            }
            assert!(
                strongest >= 2.0 / 255.0,
                "rays disappeared: {sun:?}, contrast={strongest}"
            );
            assert!(
                darkened < open.len() / 4,
                "narrow blocker darkened most receivers: {darkened}/{}",
                open.len()
            );
        }
    }
}

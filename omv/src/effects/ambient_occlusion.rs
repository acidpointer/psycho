//! Engine-side ambient occlusion pipeline.

use libpsycho::os::windows::directx9::{
    D3DCULL_NONE, D3DFMT_G16R16F, D3DFORMAT, D3DPT_TRIANGLESTRIP, D3DRS_ALPHABLENDENABLE,
    D3DRS_ALPHATESTENABLE, D3DRS_COLORWRITEENABLE, D3DRS_CULLMODE, D3DRS_ZENABLE,
    D3DRS_ZWRITEENABLE, D3DSAMP_ADDRESSU, D3DSAMP_ADDRESSV, D3DSAMP_MAGFILTER, D3DSAMP_MINFILTER,
    D3DSAMP_MIPFILTER, D3DSURFACE_DESC, D3DTA_TEXTURE, D3DTADDRESS_CLAMP, D3DTEXF_LINEAR,
    D3DTEXF_NONE, D3DTEXF_POINT, D3DTOP_SELECTARG1, D3DTSS_ALPHAARG1, D3DTSS_ALPHAOP,
    D3DTSS_COLORARG1, D3DTSS_COLOROP, D3DVIEWPORT9, Device9Ref, Direct3DResult, PixelShader9,
    ScreenVertex, Surface9, Texture9, direct3d_failure,
};

use crate::{
    backend::{CameraFrame, DepthTexture, FrameInputs},
    shaders::{self, ScreenShaderSource},
};

const COLOR_WRITE_ALL: u32 = 0x0F;
const CONTACT_OPTION_REGISTER: u32 = 7;
const EFFECT_CONSTANT_REGISTER: u32 = 10;
const TEMPORAL_CONSTANT_REGISTER: u32 = 13;
const AO_SCALE: u32 = 2;

const EXTRACT_SHADER: &[u8] =
    include_bytes!("../../shaders/embedded/ambient_occlusion_extract.hlsl");
const BLUR_SHADER: &[u8] = include_bytes!("../../shaders/embedded/ambient_occlusion_blur.hlsl");
const TEMPORAL_SHADER: &[u8] =
    include_bytes!("../../shaders/embedded/ambient_occlusion_temporal.hlsl");
const COMPOSE_SHADER: &[u8] =
    include_bytes!("../../shaders/embedded/ambient_occlusion_compose.hlsl");

#[cfg(test)]
mod shader_compile_tests {
    use libpsycho::os::windows::directx9::{D3DFMT_A8R8G8B8, D3DFMT_G16R16F};

    use super::{
        BLUR_SHADER, COMPOSE_SHADER, EXTRACT_SHADER, TEMPORAL_SHADER, TemporalCameraState,
        TemporalReprojection, fallback_format_matches,
    };
    use crate::backend::{CameraFrame, CameraTransformFrame};

    #[test]
    fn embedded_ambient_occlusion_shaders_compile() {
        crate::shaders::assert_hlsl_compiles(
            "ambient_occlusion_extract.hlsl",
            EXTRACT_SHADER,
            "ps_3_0",
        );
        crate::shaders::assert_hlsl_compiles("ambient_occlusion_blur.hlsl", BLUR_SHADER, "ps_3_0");
        crate::shaders::assert_hlsl_compiles(
            "ambient_occlusion_temporal.hlsl",
            TEMPORAL_SHADER,
            "ps_3_0",
        );
        crate::shaders::assert_hlsl_compiles(
            "ambient_occlusion_compose.hlsl",
            COMPOSE_SHADER,
            "ps_3_0",
        );
    }

    #[test]
    fn preferred_targets_ignore_scene_format_changes() {
        assert!(fallback_format_matches(
            false,
            D3DFMT_A8R8G8B8,
            D3DFMT_G16R16F
        ));
    }

    #[test]
    fn fallback_targets_require_the_same_scene_format() {
        assert!(fallback_format_matches(
            true,
            D3DFMT_A8R8G8B8,
            D3DFMT_A8R8G8B8
        ));
        assert!(!fallback_format_matches(
            true,
            D3DFMT_A8R8G8B8,
            D3DFMT_G16R16F
        ));
    }

    fn camera(rotation: [[f32; 3]; 3], translation: [f32; 3], scale: f32) -> CameraFrame {
        CameraFrame {
            near_z: 5.0,
            far_z: 1000.0,
            aspect_ratio: 16.0 / 9.0,
            frustum_left: -1.0,
            frustum_right: 1.0,
            frustum_bottom: -0.5,
            frustum_top: 0.5,
            world_transform: CameraTransformFrame {
                rotation,
                translation,
                scale,
                available: true,
            },
            available: true,
        }
    }

    #[test]
    fn identity_cameras_preserve_ao_view_coordinates() {
        let identity = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let camera = camera(identity, [0.0; 3], 1.0);
        let reprojection = TemporalReprojection::between(
            TemporalCameraState { camera, epoch: 4 },
            TemporalCameraState { camera, epoch: 5 },
        )
        .expect("identity reprojection");

        assert_eq!(
            reprojection.rows,
            [
                [1.0, 0.0, 0.0, 0.0],
                [0.0, 1.0, 0.0, 0.0],
                [0.0, 0.0, 1.0, 0.0],
            ]
        );
    }

    #[test]
    fn camera_translation_is_expressed_in_previous_ao_basis() {
        let identity = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let previous = camera(identity, [10.0, 20.0, 30.0], 1.0);
        let current = camera(identity, [13.0, 22.0, 35.0], 1.0);
        let reprojection = TemporalReprojection::between(
            TemporalCameraState {
                camera: previous,
                epoch: 8,
            },
            TemporalCameraState {
                camera: current,
                epoch: 9,
            },
        )
        .expect("translated reprojection");

        assert_eq!(reprojection.rows[0][3], 5.0);
        assert_eq!(reprojection.rows[1][3], 2.0);
        assert_eq!(reprojection.rows[2][3], 3.0);
    }

    #[test]
    fn camera_rotation_preserves_forward_up_right_handedness() {
        let identity = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let quarter_turn = [[0.0, -1.0, 0.0], [1.0, 0.0, 0.0], [0.0, 0.0, 1.0]];
        let reprojection = TemporalReprojection::between(
            TemporalCameraState {
                camera: camera(identity, [0.0; 3], 1.0),
                epoch: 11,
            },
            TemporalCameraState {
                camera: camera(quarter_turn, [0.0; 3], 1.0),
                epoch: 12,
            },
        )
        .expect("rotated reprojection");

        assert_eq!(
            reprojection.rows,
            [
                [1.0, 0.0, 0.0, 0.0],
                [0.0, 0.0, 1.0, 0.0],
                [0.0, -1.0, 0.0, 0.0],
            ]
        );
    }

    #[test]
    fn history_requires_a_consecutive_capture_epoch() {
        let identity = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let camera = camera(identity, [0.0; 3], 1.0);
        assert!(
            TemporalReprojection::between(
                TemporalCameraState { camera, epoch: 2 },
                TemporalCameraState { camera, epoch: 4 },
            )
            .is_none()
        );
    }
}

pub(crate) struct AmbientOcclusionEffect {
    extract_shader: PixelShader9,
    blur_shader: PixelShader9,
    temporal_shader: PixelShader9,
    compose_shader: PixelShader9,
    targets: Option<AmbientOcclusionTargets>,
    previous_camera: Option<TemporalCameraState>,
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
            temporal_shader: compile_shader(
                device,
                "ambient_occlusion_temporal.hlsl",
                TEMPORAL_SHADER,
            )?,
            compose_shader: compile_shader(
                device,
                "ambient_occlusion_compose.hlsl",
                COMPOSE_SHADER,
            )?,
            targets: None,
            previous_camera: None,
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
        let current_camera = TemporalCameraState {
            camera: frame_inputs.depth.world_projection.camera,
            epoch: frame_inputs.depth.capture_epoch,
        };
        let reprojection = self
            .previous_camera
            .and_then(|previous| TemporalReprojection::between(previous, current_camera));
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
        self.draw_temporal(
            device,
            targets,
            desc,
            frame_inputs,
            fast_source,
            contact_source,
            frame_index,
            reprojection,
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
        )?;

        device.clear_texture(4)?;
        device.stretch_rect(
            &targets.blur.surface,
            None,
            &targets.history.surface,
            None,
            D3DTEXF_POINT,
        )?;
        self.previous_camera = Some(current_camera);
        Ok(())
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
            .is_none_or(|targets| !targets.matches(width, height, format));
        if needs_targets {
            let targets = AmbientOcclusionTargets::create(device, width, height, format)?;
            log::info!(
                "[AO] Intermediate targets: {}x{}, format={}, fallback={}",
                width,
                height,
                targets.format.0,
                targets.used_fallback
            );
            self.targets = Some(targets);
            self.previous_camera = None;
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

    #[allow(clippy::too_many_arguments)]
    fn draw_temporal(
        &self,
        device: &Device9Ref<'_>,
        targets: &AmbientOcclusionTargets,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &FrameInputs,
        fast_source: Option<&ScreenShaderSource>,
        contact_source: Option<&ScreenShaderSource>,
        frame_index: u32,
        reprojection: Option<TemporalReprojection>,
    ) -> Direct3DResult<()> {
        bind_target(device, &targets.blur.surface, targets.width, targets.height)?;
        device.set_texture(0, &targets.occlusion.texture)?;
        device.set_texture(4, &targets.history.texture)?;
        bind_depth_inputs(
            device,
            &frame_inputs.depth.texture,
            &frame_inputs.depth.first_person_texture,
        )?;
        bind_fullres_constants(
            device,
            desc,
            frame_inputs,
            fast_source,
            contact_source,
            frame_index,
            1.5,
        )?;

        let stability = temporal_stability(fast_source, contact_source);
        let constants = reprojection.map_or_else(
            || TemporalShaderConstants::invalid(targets, stability),
            |reprojection| TemporalShaderConstants::valid(targets, stability, reprojection),
        );
        device.set_pixel_shader_constant_f(TEMPORAL_CONSTANT_REGISTER, &constants.registers)?;
        device.set_pixel_shader(&self.temporal_shader)?;
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
        device.set_texture(4, &targets.blur.texture)?;
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

#[derive(Clone, Copy)]
struct TemporalCameraState {
    camera: CameraFrame,
    epoch: u64,
}

#[derive(Clone, Copy, Debug)]
struct TemporalReprojection {
    rows: [[f32; 4]; 3],
    previous_frustum: [f32; 4],
    previous_depth: [f32; 2],
}

impl TemporalReprojection {
    fn between(previous: TemporalCameraState, current: TemporalCameraState) -> Option<Self> {
        if current.epoch != previous.epoch.wrapping_add(1)
            || !camera_supports_reprojection(previous.camera)
            || !camera_supports_reprojection(current.camera)
        {
            return None;
        }

        let previous_transform = previous.camera.world_transform;
        let current_transform = current.camera.world_transform;
        let scale_ratio = current_transform.scale / previous_transform.scale;
        let mut rotation = [[0.0; 3]; 3];
        for (row, output_row) in rotation.iter_mut().enumerate() {
            for (column, output) in output_row.iter_mut().enumerate() {
                *output = (0..3)
                    .map(|axis| {
                        previous_transform.rotation[axis][2 - row]
                            * current_transform.rotation[axis][2 - column]
                    })
                    .sum::<f32>()
                    * scale_ratio;
            }
        }

        let translation_delta = [
            current_transform.translation[0] - previous_transform.translation[0],
            current_transform.translation[1] - previous_transform.translation[1],
            current_transform.translation[2] - previous_transform.translation[2],
        ];
        let mut translation = [0.0; 3];
        for (row, output) in translation.iter_mut().enumerate() {
            let previous_game_axis = 2 - row;
            *output = (0..3)
                .map(|axis| {
                    previous_transform.rotation[axis][previous_game_axis] * translation_delta[axis]
                })
                .sum::<f32>()
                / previous_transform.scale;
        }

        if rotation
            .iter()
            .flatten()
            .chain(translation.iter())
            .any(|value| !value.is_finite())
        {
            return None;
        }

        Some(Self {
            rows: [
                [
                    rotation[0][0],
                    rotation[0][1],
                    rotation[0][2],
                    translation[0],
                ],
                [
                    rotation[1][0],
                    rotation[1][1],
                    rotation[1][2],
                    translation[1],
                ],
                [
                    rotation[2][0],
                    rotation[2][1],
                    rotation[2][2],
                    translation[2],
                ],
            ],
            previous_frustum: [
                previous.camera.frustum_left,
                previous.camera.frustum_right,
                previous.camera.frustum_bottom,
                previous.camera.frustum_top,
            ],
            previous_depth: [previous.camera.near_z, previous.camera.far_z],
        })
    }
}

fn camera_supports_reprojection(camera: CameraFrame) -> bool {
    let transform = camera.world_transform;
    camera.available
        && transform.available
        && transform.scale.is_finite()
        && transform.scale.abs() > f32::EPSILON
        && transform
            .rotation
            .iter()
            .flatten()
            .chain(transform.translation.iter())
            .all(|value| value.is_finite())
}

struct TemporalShaderConstants {
    registers: [[f32; 4]; 6],
}

impl TemporalShaderConstants {
    fn invalid(targets: &AmbientOcclusionTargets, stability: f32) -> Self {
        Self {
            registers: [
                [1.0, 0.0, 0.0, 0.0],
                [0.0, 1.0, 0.0, 0.0],
                [0.0, 0.0, 1.0, 0.0],
                [-1.0, 1.0, -1.0, 1.0],
                [0.0, stability, 0.01, 1.0],
                [targets.inv_width, targets.inv_height, 52.0, 0.0],
            ],
        }
    }

    fn valid(
        targets: &AmbientOcclusionTargets,
        stability: f32,
        reprojection: TemporalReprojection,
    ) -> Self {
        Self {
            registers: [
                reprojection.rows[0],
                reprojection.rows[1],
                reprojection.rows[2],
                reprojection.previous_frustum,
                [
                    1.0,
                    stability,
                    reprojection.previous_depth[0],
                    reprojection.previous_depth[1],
                ],
                [targets.inv_width, targets.inv_height, 52.0, 0.0],
            ],
        }
    }
}

fn temporal_stability(
    fast_source: Option<&ScreenShaderSource>,
    contact_source: Option<&ScreenShaderSource>,
) -> f32 {
    let fast = fast_source.map(|source| {
        (
            source.option_constants[0][0].max(0.0),
            source.option_constants[2][0].clamp(0.0, 1.0),
        )
    });
    let contact = contact_source.map(|source| {
        (
            source.option_constants[0][0].max(0.0),
            source.option_constants[1][3].clamp(0.0, 1.0),
        )
    });
    let total_strength = fast.map_or(0.0, |value| value.0) + contact.map_or(0.0, |value| value.0);
    if total_strength <= f32::EPSILON {
        return 0.0;
    }

    let weighted_stability = fast.map_or(0.0, |value| value.0 * value.1)
        + contact.map_or(0.0, |value| value.0 * value.1);
    (weighted_stability / total_strength).clamp(0.0, 1.0)
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
    format: D3DFORMAT,
    fallback_format: D3DFORMAT,
    used_fallback: bool,
    occlusion: EffectTarget,
    blur: EffectTarget,
    history: EffectTarget,
}

impl AmbientOcclusionTargets {
    fn create(
        device: &Device9Ref<'_>,
        width: u32,
        height: u32,
        fallback_format: D3DFORMAT,
    ) -> Direct3DResult<Self> {
        let (occlusion, blur, history, format, used_fallback) = match (
            EffectTarget::create(device, width, height, D3DFMT_G16R16F),
            EffectTarget::create(device, width, height, D3DFMT_G16R16F),
            EffectTarget::create(device, width, height, D3DFMT_G16R16F),
        ) {
            (Ok(occlusion), Ok(blur), Ok(history)) => {
                (occlusion, blur, history, D3DFMT_G16R16F, false)
            }
            (Err(err), _, _) | (_, Err(err), _) | (_, _, Err(err)) => {
                log::warn!(
                    "[AO] G16R16F targets unavailable ({err}); falling back to scene format"
                );
                (
                    EffectTarget::create(device, width, height, fallback_format)?,
                    EffectTarget::create(device, width, height, fallback_format)?,
                    EffectTarget::create(device, width, height, fallback_format)?,
                    fallback_format,
                    true,
                )
            }
        };

        Ok(Self {
            width,
            height,
            inv_width: 1.0 / width as f32,
            inv_height: 1.0 / height as f32,
            format,
            fallback_format,
            used_fallback,
            occlusion,
            blur,
            history,
        })
    }

    fn matches(&self, width: u32, height: u32, fallback_format: D3DFORMAT) -> bool {
        self.width == width
            && self.height == height
            && fallback_format_matches(self.used_fallback, self.fallback_format, fallback_format)
    }
}

fn fallback_format_matches(
    used_fallback: bool,
    active_format: D3DFORMAT,
    requested_format: D3DFORMAT,
) -> bool {
    !used_fallback || active_format == requested_format
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

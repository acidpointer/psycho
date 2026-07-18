//! World-only temporal anti-aliasing resolved before first-person and UI rendering.

use libpsycho::os::windows::directx9::{
    D3DCULL_NONE, D3DFMT_A16B16G16R16F, D3DFMT_R16F, D3DFORMAT, D3DPT_TRIANGLESTRIP,
    D3DRS_ALPHABLENDENABLE, D3DRS_ALPHATESTENABLE, D3DRS_COLORWRITEENABLE, D3DRS_CULLMODE,
    D3DRS_ZENABLE, D3DRS_ZWRITEENABLE, D3DSAMP_ADDRESSU, D3DSAMP_ADDRESSV, D3DSAMP_MAGFILTER,
    D3DSAMP_MINFILTER, D3DSAMP_MIPFILTER, D3DSURFACE_DESC, D3DTA_TEXTURE, D3DTADDRESS_CLAMP,
    D3DTEXF_LINEAR, D3DTEXF_NONE, D3DTEXF_POINT, D3DTOP_SELECTARG1, D3DTSS_ALPHAARG1,
    D3DTSS_ALPHAOP, D3DTSS_COLORARG1, D3DTSS_COLOROP, D3DVIEWPORT9, Device9Ref, Direct3DResult,
    PixelShader9, ScreenVertex, Surface9, Texture9, direct3d_failure,
};

use crate::{
    backend::{CameraFrame, DepthFrame},
    shaders::{self, ScreenShaderSource},
};

const COLOR_WRITE_ALL: u32 = 0x0F;
const OPTION_REGISTER: u32 = 3;
const REPROJECTION_REGISTER: u32 = 5;
const TARGET_RETRY_FRAMES: u16 = 120;
const TAA_SHADER: &[u8] = include_bytes!("../../shaders/embedded/aa_temporal.hlsl");
const DEPTH_KEY_SHADER: &[u8] = include_bytes!("../../shaders/embedded/aa_temporal_depth_key.hlsl");

#[derive(Clone, Copy)]
pub(crate) struct TemporalAaConfig {
    options: [f32; 4],
}

impl TemporalAaConfig {
    pub(crate) fn from_source(source: &ScreenShaderSource) -> Self {
        Self {
            options: source.option_constants.first().copied().unwrap_or_default(),
        }
    }

    pub(crate) fn jitter_scale(self) -> f32 {
        self.options[3].clamp(0.0, 1.5)
    }
}

#[cfg(test)]
mod shader_compile_tests {
    use super::{DEPTH_KEY_SHADER, TAA_SHADER, TemporalCameraState, TemporalReprojection};
    use crate::backend::{CameraFrame, CameraTransformFrame};

    fn camera(rotation: [[f32; 3]; 3], translation: [f32; 3]) -> CameraFrame {
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
                scale: 1.0,
                available: true,
            },
            available: true,
        }
    }

    #[test]
    fn embedded_temporal_aa_shader_compiles() {
        crate::shaders::assert_hlsl_compiles("aa_temporal.hlsl", TAA_SHADER, "ps_3_0");
        crate::shaders::assert_hlsl_compiles(
            "aa_temporal_depth_key.hlsl",
            DEPTH_KEY_SHADER,
            "ps_3_0",
        );
    }

    #[test]
    fn temporal_neighborhood_reuses_current_color_sample() {
        let source = std::str::from_utf8(TAA_SHADER).expect("TAA source is UTF-8");
        assert!(source.contains("Neighborhood(uv, current.rgb, low, high, average)"));
        assert!(
            !source.contains("float3 center = tex2Dlod(CurrentColor, float4(uv, 0.0, 0.0)).rgb;")
        );
    }

    #[test]
    fn temporal_resolve_keeps_depth_keys_out_of_world_alpha() {
        let source = std::str::from_utf8(TAA_SHADER).expect("TAA source is UTF-8");
        assert!(source.contains("sampler2D HistoryDepthKey : register(s3)"));
        assert!(source.contains("return float4(resolved, current.a)"));
        assert!(!source.contains("history.a - expectedKey"));
        assert!(!source.contains("return float4(current, currentKey)"));
    }

    #[test]
    fn identity_camera_has_valid_reprojection() {
        let identity = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let camera = camera(identity, [0.0; 3]);
        assert!(
            TemporalReprojection::between(
                TemporalCameraState { camera, epoch: 4 },
                TemporalCameraState { camera, epoch: 5 },
            )
            .is_some()
        );
    }

    #[test]
    fn history_rejects_epoch_gaps_and_camera_cuts() {
        let identity = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let previous = camera(identity, [0.0; 3]);
        assert!(
            TemporalReprojection::between(
                TemporalCameraState {
                    camera: previous,
                    epoch: 2,
                },
                TemporalCameraState {
                    camera: previous,
                    epoch: 4,
                },
            )
            .is_none()
        );

        let teleported = camera(identity, [300.0, 0.0, 0.0]);
        assert!(
            TemporalReprojection::between(
                TemporalCameraState {
                    camera: previous,
                    epoch: 7,
                },
                TemporalCameraState {
                    camera: teleported,
                    epoch: 8,
                },
            )
            .is_none()
        );
    }
}

pub(crate) struct TemporalAaEffect {
    shader: PixelShader9,
    depth_key_shader: PixelShader9,
    targets: Option<TemporalTargets>,
    previous_camera: Option<TemporalCameraState>,
    history_index: usize,
    history_valid: bool,
    failed_target: Option<TargetDescription>,
    target_retry_frames: u16,
}

impl TemporalAaEffect {
    pub(crate) fn create(device: &Device9Ref<'_>) -> Direct3DResult<Self> {
        Ok(Self {
            shader: compile_shader(device, "aa_temporal.hlsl", TAA_SHADER)?,
            depth_key_shader: compile_shader(
                device,
                "aa_temporal_depth_key.hlsl",
                DEPTH_KEY_SHADER,
            )?,
            targets: None,
            previous_camera: None,
            history_index: 0,
            history_valid: false,
            failed_target: None,
            target_retry_frames: 0,
        })
    }

    pub(crate) fn invalidate_history(&mut self) {
        self.previous_camera = None;
        self.history_valid = false;
    }

    pub(crate) fn can_jitter(
        &self,
        camera: CameraFrame,
        epoch: u64,
        target: TargetDescription,
    ) -> bool {
        self.history_valid
            && self
                .targets
                .as_ref()
                .is_some_and(|targets| targets.matches_description(target))
            && self.previous_camera.is_some_and(|previous| {
                TemporalReprojection::between(previous, TemporalCameraState { camera, epoch })
                    .is_some()
            })
    }

    pub(crate) fn alpha_preserving_history_ready(&self, target: TargetDescription) -> bool {
        self.history_valid
            && self
                .targets
                .as_ref()
                .is_some_and(|targets| targets.matches_description(target))
    }

    pub(crate) fn draw(
        &mut self,
        device: &Device9Ref<'_>,
        render_target: &Surface9,
        desc: &D3DSURFACE_DESC,
        depth: DepthFrame,
        config: TemporalAaConfig,
    ) -> Direct3DResult<()> {
        let Some(depth_texture) = depth.texture else {
            self.invalidate_history();
            return Ok(());
        };
        if depth.world_projection.reversed_depth.is_none()
            || !camera_supports_reprojection(depth.world_projection.camera)
        {
            self.invalidate_history();
            return Ok(());
        }

        let target = TargetDescription::from(desc);
        if self.failed_target == Some(target) {
            if self.target_retry_frames > 0 {
                self.target_retry_frames -= 1;
                self.invalidate_history();
                return Ok(());
            }
            self.failed_target = None;
        }
        let targets_changed = match self.ensure_targets(device, desc) {
            Ok(changed) => changed,
            Err(err) => {
                self.failed_target = Some(target);
                self.target_retry_frames = TARGET_RETRY_FRAMES;
                self.invalidate_history();
                return Err(err);
            }
        };
        self.failed_target = None;
        self.target_retry_frames = 0;
        if targets_changed {
            self.invalidate_history();
        }
        let current_camera = TemporalCameraState {
            camera: depth.world_projection.camera,
            epoch: depth.capture_epoch,
        };
        let reprojection = self
            .previous_camera
            .and_then(|previous| TemporalReprojection::between(previous, current_camera));
        let history_available = self.history_valid && reprojection.is_some();
        let Some(targets) = self.targets.as_ref() else {
            return Ok(());
        };

        device.stretch_rect(
            render_target,
            None,
            &targets.current.surface,
            None,
            D3DTEXF_POINT,
        )?;
        let read_index = self.history_index;
        let write_index = 1 - read_index;

        bind_pipeline_state(device)?;
        bind_target(device, &targets.color_history[write_index].surface, desc)?;
        device.set_texture(0, &targets.current.texture)?;
        unsafe {
            device.set_raw_base_texture(1, depth_texture.as_ptr())?;
        }
        device.set_texture(2, &targets.color_history[read_index].texture)?;
        device.set_texture(3, &targets.depth_key_history[read_index].texture)?;
        bind_constants(device, desc, depth, config, reprojection, history_available)?;
        device.set_pixel_shader(&self.shader)?;
        draw_quad(device, desc)?;

        device.clear_texture(0)?;
        device.clear_texture(1)?;
        device.clear_texture(2)?;
        device.clear_texture(3)?;
        bind_target(
            device,
            &targets.depth_key_history[write_index].surface,
            desc,
        )?;
        unsafe {
            device.set_raw_base_texture(0, depth_texture.as_ptr())?;
        }
        device.set_sampler_state(0, D3DSAMP_MINFILTER, D3DTEXF_POINT.0 as u32)?;
        device.set_sampler_state(0, D3DSAMP_MAGFILTER, D3DTEXF_POINT.0 as u32)?;
        bind_depth_key_constants(device, depth)?;
        device.set_pixel_shader(&self.depth_key_shader)?;
        draw_quad(device, desc)?;

        device.clear_texture(0)?;
        device.stretch_rect(
            &targets.color_history[write_index].surface,
            None,
            render_target,
            None,
            D3DTEXF_POINT,
        )?;

        self.history_index = write_index;
        self.history_valid = true;
        self.previous_camera = Some(current_camera);
        Ok(())
    }

    fn ensure_targets(
        &mut self,
        device: &Device9Ref<'_>,
        desc: &D3DSURFACE_DESC,
    ) -> Direct3DResult<bool> {
        let needs_targets = self
            .targets
            .as_ref()
            .is_none_or(|targets| !targets.matches(desc));
        if needs_targets {
            self.targets = Some(TemporalTargets::create(device, desc)?);
            log::info!("[TAA] History targets: {}x{}", desc.Width, desc.Height);
        }
        Ok(needs_targets)
    }
}

#[derive(Clone, Copy)]
struct TemporalCameraState {
    camera: CameraFrame,
    epoch: u64,
}

#[derive(Clone, Copy)]
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
        let forward_alignment = (0..3)
            .map(|axis| previous_transform.rotation[axis][0] * current_transform.rotation[axis][0])
            .sum::<f32>();
        let camera_cut_distance = previous.camera.far_z.min(current.camera.far_z) * 0.25;
        let translation_distance_squared =
            translation.iter().map(|value| value * value).sum::<f32>();
        if forward_alignment < 0.5
            || translation_distance_squared > camera_cut_distance * camera_cut_distance
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

fn bind_constants(
    device: &Device9Ref<'_>,
    desc: &D3DSURFACE_DESC,
    depth: DepthFrame,
    config: TemporalAaConfig,
    reprojection: Option<TemporalReprojection>,
    history_available: bool,
) -> Direct3DResult<()> {
    let camera = depth.world_projection.camera;
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
                camera.frustum_left,
                camera.frustum_right,
                camera.frustum_bottom,
                camera.frustum_top,
            ],
            [
                camera.near_z,
                camera.far_z,
                depth.world_projection.reversed_depth_f32(),
                if history_available { 1.0 } else { 0.0 },
            ],
        ],
    )?;
    device.set_pixel_shader_constant_f(OPTION_REGISTER, &[config.options])?;
    let reprojection_constants = reprojection.map_or_else(
        || {
            [
                [1.0, 0.0, 0.0, 0.0],
                [0.0, 1.0, 0.0, 0.0],
                [0.0, 0.0, 1.0, 0.0],
                [-1.0, 1.0, -1.0, 1.0],
                [0.0, 1.0, 0.0, 0.0],
            ]
        },
        |reprojection| {
            [
                reprojection.rows[0],
                reprojection.rows[1],
                reprojection.rows[2],
                reprojection.previous_frustum,
                [
                    reprojection.previous_depth[0],
                    reprojection.previous_depth[1],
                    52.0,
                    0.0,
                ],
            ]
        },
    );
    device.set_pixel_shader_constant_f(REPROJECTION_REGISTER, &reprojection_constants)
}

fn bind_depth_key_constants(device: &Device9Ref<'_>, depth: DepthFrame) -> Direct3DResult<()> {
    let camera = depth.world_projection.camera;
    device.set_pixel_shader_constant_f(
        0,
        &[[
            camera.near_z,
            camera.far_z,
            depth.world_projection.reversed_depth_f32(),
            0.0,
        ]],
    )
}

fn compile_shader(
    device: &Device9Ref<'_>,
    source_name: &str,
    source: &[u8],
) -> Direct3DResult<PixelShader9> {
    let bytecode = match shaders::compile_hlsl_source(source_name, source) {
        Ok(bytecode) => bytecode,
        Err(err) => {
            log::warn!("[TAA] Failed to compile {source_name}: {err:#}");
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
    for sampler in 0..=3 {
        let filter = if sampler == 1 || sampler == 3 {
            D3DTEXF_POINT
        } else {
            D3DTEXF_LINEAR
        };
        device.set_sampler_state(sampler, D3DSAMP_ADDRESSU, D3DTADDRESS_CLAMP.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_ADDRESSV, D3DTADDRESS_CLAMP.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_MINFILTER, filter.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_MAGFILTER, filter.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_MIPFILTER, D3DTEXF_NONE.0 as u32)?;
    }
    device.set_texture_stage_state(0, D3DTSS_COLOROP, D3DTOP_SELECTARG1.0 as u32)?;
    device.set_texture_stage_state(0, D3DTSS_COLORARG1, D3DTA_TEXTURE)?;
    device.set_texture_stage_state(0, D3DTSS_ALPHAOP, D3DTOP_SELECTARG1.0 as u32)?;
    device.set_texture_stage_state(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE)
}

fn bind_target(
    device: &Device9Ref<'_>,
    surface: &Surface9,
    desc: &D3DSURFACE_DESC,
) -> Direct3DResult<()> {
    device.clear_texture(0)?;
    device.set_render_target(0, surface)?;
    device.set_viewport(&D3DVIEWPORT9 {
        X: 0,
        Y: 0,
        Width: desc.Width,
        Height: desc.Height,
        MinZ: 0.0,
        MaxZ: 1.0,
    })
}

fn draw_quad(device: &Device9Ref<'_>, desc: &D3DSURFACE_DESC) -> Direct3DResult<()> {
    let width = desc.Width as f32;
    let height = desc.Height as f32;
    let quad = [
        ScreenVertex::new(-0.5, -0.5, 0.0, 0.0),
        ScreenVertex::new(width - 0.5, -0.5, 1.0, 0.0),
        ScreenVertex::new(-0.5, height - 0.5, 0.0, 1.0),
        ScreenVertex::new(width - 0.5, height - 0.5, 1.0, 1.0),
    ];
    unsafe { device.draw_primitive_up(D3DPT_TRIANGLESTRIP, 2, &quad) }
}

struct TemporalTargets {
    current: EffectTarget,
    color_history: [EffectTarget; 2],
    depth_key_history: [EffectTarget; 2],
}

impl TemporalTargets {
    fn create(device: &Device9Ref<'_>, desc: &D3DSURFACE_DESC) -> Direct3DResult<Self> {
        let color_history = [
            EffectTarget::create(device, desc.Width, desc.Height, D3DFMT_A16B16G16R16F)?,
            EffectTarget::create(device, desc.Width, desc.Height, D3DFMT_A16B16G16R16F)?,
        ];
        let depth_key_history = [
            EffectTarget::create(device, desc.Width, desc.Height, D3DFMT_R16F)?,
            EffectTarget::create(device, desc.Width, desc.Height, D3DFMT_R16F)?,
        ];
        Ok(Self {
            current: EffectTarget::create(device, desc.Width, desc.Height, desc.Format)?,
            color_history,
            depth_key_history,
        })
    }

    fn matches(&self, desc: &D3DSURFACE_DESC) -> bool {
        self.current.width == desc.Width
            && self.current.height == desc.Height
            && self.current.format == desc.Format
    }

    fn matches_description(&self, target: TargetDescription) -> bool {
        self.current.width == target.width
            && self.current.height == target.height
            && self.current.format == target.format
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct TargetDescription {
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) format: D3DFORMAT,
}

impl From<&D3DSURFACE_DESC> for TargetDescription {
    fn from(desc: &D3DSURFACE_DESC) -> Self {
        Self {
            width: desc.Width,
            height: desc.Height,
            format: desc.Format,
        }
    }
}

struct EffectTarget {
    texture: Texture9,
    surface: Surface9,
    width: u32,
    height: u32,
    format: D3DFORMAT,
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
        Ok(Self {
            texture,
            surface,
            width,
            height,
            format,
        })
    }
}

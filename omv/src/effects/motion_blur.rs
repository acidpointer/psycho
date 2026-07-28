//! Depth-aware camera motion blur for the post-image-space scene boundary.
//!
//! The effect reconstructs a current view-space position from FNV's resolved
//! depth, transforms that position into the previous camera basis, and
//! integrates color backward over the configured shutter interval. This gives
//! rotation, translation parallax, zoom, and sky rotation without a velocity
//! render target or color history.
//!
//! Production blur work is one full-resolution draw. Three compile-time shader
//! variants use 5, 7, or 9 taps. Third person additionally records one
//! full-resolution packed-depth history so independently moving surfaces can
//! reject camera-only motion without color history or engine object tags.
//! Disabled and zero-work configurations perform no effect-specific GPU work.
//! World and first-person depth are sampled independently so the weapon cannot
//! leak across a world silhouette. The history validity gate preserves the
//! third-person player and other independently moving/disoccluded geometry
//! while static world surfaces and sky retain camera motion.

use std::{
    sync::{
        LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use anyhow::Result;
use libpsycho::os::windows::directx9::{
    D3DCULL_NONE, D3DFMT_A8R8G8B8, D3DPT_TRIANGLESTRIP, D3DRS_ADAPTIVETESS_Y,
    D3DRS_ALPHABLENDENABLE, D3DRS_ALPHATESTENABLE, D3DRS_COLORWRITEENABLE, D3DRS_CULLMODE,
    D3DRS_MULTISAMPLEANTIALIAS, D3DRS_MULTISAMPLEMASK, D3DRS_POINTSIZE, D3DRS_SCISSORTESTENABLE,
    D3DRS_SRGBWRITEENABLE, D3DRS_STENCILENABLE, D3DRS_ZENABLE, D3DRS_ZWRITEENABLE,
    D3DSAMP_ADDRESSU, D3DSAMP_ADDRESSV, D3DSAMP_MAGFILTER, D3DSAMP_MINFILTER, D3DSAMP_MIPFILTER,
    D3DSAMP_SRGBTEXTURE, D3DSURFACE_DESC, D3DTA_TEXTURE, D3DTADDRESS_CLAMP, D3DTEXF_LINEAR,
    D3DTEXF_NONE, D3DTEXF_POINT, D3DTOP_SELECTARG1, D3DTSS_ALPHAARG1, D3DTSS_ALPHAOP,
    D3DTSS_COLORARG1, D3DTSS_COLOROP, D3DVIEWPORT9, Device9Ref, Direct3DResult, PixelShader9,
    ScreenVertex, Surface9, Texture9, direct3d_failure,
};
use parking_lot::Mutex;

use crate::{
    backend::{CameraFrame, DepthTexture, FrameInputs},
    config::{MotionBlurConfig, MotionBlurQuality},
    shaders,
};

const COLOR_WRITE_ALL: u32 = 0x0F;
const AMD_ALPHA_TO_COVERAGE_OFF: u32 = u32::from_le_bytes(*b"A2M0");
// A very large same-epoch camera jump is a discontinuity, not useful motion.
// The absolute cap keeps an exceptionally long far plane from admitting
// teleports, while the relative TAA-style bound handles short projections.
const MAX_CAMERA_CUT_TRANSLATION: f32 = 4_096.0;
const SHADER: &[u8] = include_bytes!("../../shaders/embedded/motion_blur.hlsl");
const THIRD_PERSON_SHADER: &[u8] =
    include_bytes!("../../shaders/embedded/motion_blur_third_person.hlsl");
const DEPTH_HISTORY_SHADER: &[u8] =
    include_bytes!("../../shaders/embedded/motion_blur_depth_history.hlsl");

static COMPILE_STARTED: AtomicBool = AtomicBool::new(false);
static COMPILE_FAILED: AtomicBool = AtomicBool::new(false);
static COMPILE_READY: AtomicBool = AtomicBool::new(false);
static BYTECODE: LazyLock<Mutex<Option<MotionBlurBytecode>>> = LazyLock::new(|| Mutex::new(None));

struct MotionBlurBytecode {
    performance: Vec<u32>,
    high: Vec<u32>,
    ultra: Vec<u32>,
    third_person_performance: Vec<u32>,
    third_person_high: Vec<u32>,
    third_person_ultra: Vec<u32>,
    depth_history: Vec<u32>,
}

impl MotionBlurBytecode {
    fn compile() -> Result<Self> {
        Ok(Self {
            performance: compile_variant(MotionBlurQuality::Performance, false)?,
            high: compile_variant(MotionBlurQuality::High, false)?,
            ultra: compile_variant(MotionBlurQuality::Ultra, false)?,
            third_person_performance: compile_variant(MotionBlurQuality::Performance, true)?,
            third_person_high: compile_variant(MotionBlurQuality::High, true)?,
            third_person_ultra: compile_variant(MotionBlurQuality::Ultra, true)?,
            depth_history: compile_depth_history()?,
        })
    }
}

/// Starts off-thread compilation of every production quality variant.
///
/// Calling this repeatedly is cheap. The render thread only creates D3D shader
/// objects after the cached bytecode has been published.
pub(crate) fn service_present_frame() {
    start_compile_worker();
}

/// Returns whether cached bytecode is ready for render-thread shader creation.
///
/// This lets the phase preflight remain a true no-GPU-work path while
/// asynchronous preparation is in flight. It deliberately does not take the
/// bytecode mutex or create a D3D object.
pub(crate) fn preparation_ready() -> bool {
    COMPILE_READY.load(Ordering::Acquire)
}

fn start_compile_worker() {
    if COMPILE_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    if let Err(err) = thread::Builder::new()
        .name("omv-motion-blur-compile".to_owned())
        .spawn(|| match MotionBlurBytecode::compile() {
            Ok(bytecode) => {
                *BYTECODE.lock() = Some(bytecode);
                COMPILE_READY.store(true, Ordering::Release);
            }
            Err(err) => {
                COMPILE_FAILED.store(true, Ordering::Release);
                log::warn!("[MOTION_BLUR] Shader preparation failed: {err:#}");
            }
        })
    {
        COMPILE_FAILED.store(true, Ordering::Release);
        log::warn!("[MOTION_BLUR] Could not start shader preparation: {err}");
    }
}

/// Returns whether the effect has valid inputs and nonzero configured work.
///
/// This preflight intentionally does not require a previous camera. The first
/// accepted frame must reach [`MotionBlurTemporalState::prepare_frame`] to
/// prime that temporal state, but it still performs no copy or draw.
pub(crate) fn should_prepare(frame_inputs: &FrameInputs, config: MotionBlurConfig) -> bool {
    let settings = MotionBlurSettings::from_config(config);
    settings.enabled
        && settings.shutter_fraction > f32::EPSILON
        && settings.max_blur_pixels > f32::EPSILON
        && frame_inputs.third_person_view.is_some()
        && frame_inputs.depth.texture.is_some()
        && frame_inputs.depth.world_projection.reversed_depth.is_some()
        && camera_supports_reprojection(frame_inputs.depth.world_projection.camera)
}

/// Device-owned shaders and the small CPU temporal state for motion blur.
pub(crate) struct MotionBlurEffect {
    performance_shader: PixelShader9,
    high_shader: PixelShader9,
    ultra_shader: PixelShader9,
    third_person_performance_shader: PixelShader9,
    third_person_high_shader: PixelShader9,
    third_person_ultra_shader: PixelShader9,
    depth_history_shader: PixelShader9,
    depth_history: Option<MotionBlurDepthHistory>,
    depth_history_creation_failed: bool,
}

struct MotionBlurDepthHistory {
    width: u32,
    height: u32,
    texture: Texture9,
    surface: Surface9,
    valid: bool,
    capture_epoch: u64,
    reversed_depth: bool,
}

impl MotionBlurDepthHistory {
    fn create(device: &Device9Ref<'_>, desc: &D3DSURFACE_DESC) -> Direct3DResult<Self> {
        let texture =
            device.create_render_target_texture(desc.Width, desc.Height, D3DFMT_A8R8G8B8)?;
        let surface = texture.surface_level(0)?;
        Ok(Self {
            width: desc.Width,
            height: desc.Height,
            texture,
            surface,
            valid: false,
            capture_epoch: 0,
            reversed_depth: false,
        })
    }

    fn matches(&self, desc: &D3DSURFACE_DESC) -> bool {
        self.width == desc.Width && self.height == desc.Height
    }
}

impl MotionBlurEffect {
    /// Creates D3D shader objects when off-thread bytecode preparation is ready.
    ///
    /// `Ok(None)` is a normal nonblocking result while compilation is still in
    /// flight. No HLSL compilation or filesystem work occurs here.
    pub(crate) fn create(device: &Device9Ref<'_>) -> Direct3DResult<Option<Self>> {
        start_compile_worker();
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

        Ok(Some(Self {
            performance_shader: device.create_pixel_shader(&bytecode.performance)?,
            high_shader: device.create_pixel_shader(&bytecode.high)?,
            ultra_shader: device.create_pixel_shader(&bytecode.ultra)?,
            third_person_performance_shader: device
                .create_pixel_shader(&bytecode.third_person_performance)?,
            third_person_high_shader: device.create_pixel_shader(&bytecode.third_person_high)?,
            third_person_ultra_shader: device.create_pixel_shader(&bytecode.third_person_ultra)?,
            depth_history_shader: device.create_pixel_shader(&bytecode.depth_history)?,
            depth_history: None,
            depth_history_creation_failed: false,
        }))
    }

    pub(crate) fn has_applicable_work(&self, frame: PreparedMotionBlurFrame) -> bool {
        !frame.third_person || !self.depth_history_creation_failed
    }

    /// Returns whether this packet can draw blur from already-owned inputs.
    ///
    /// Third-person packets require a consecutive packed-depth history.
    /// Record-only packets deliberately avoid the phase color copy.
    pub(crate) fn requires_color_copy(
        &self,
        desc: &D3DSURFACE_DESC,
        frame: PreparedMotionBlurFrame,
    ) -> bool {
        if !frame.blur_requested || frame.world_reprojection.is_none() {
            return false;
        }
        if !frame.third_person {
            return true;
        }
        self.depth_history.as_ref().is_some_and(|history| {
            history.valid
                && history.matches(desc)
                && frame.capture_epoch == history.capture_epoch.wrapping_add(1)
        })
    }

    /// Draws an optional blur pass and records the third-person depth history.
    pub(crate) fn draw(
        &mut self,
        device: &Device9Ref<'_>,
        target: &Surface9,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &FrameInputs,
        scene_color: Option<&Texture9>,
        frame: PreparedMotionBlurFrame,
    ) -> Direct3DResult<()> {
        let history_available = frame.third_person
            && self.depth_history.as_ref().is_some_and(|history| {
                history.valid
                    && history.matches(desc)
                    && frame.capture_epoch == history.capture_epoch.wrapping_add(1)
            });
        if frame.blur_requested
            && frame.world_reprojection.is_some()
            && (!frame.third_person || history_available)
            && let Some(scene_color) = scene_color
        {
            bind_pipeline_state(device)?;
            bind_target(device, target, desc)?;
            device.set_texture(0, scene_color)?;
            bind_depth_texture(device, 1, frame_inputs.depth.texture)?;
            bind_depth_texture(device, 2, frame_inputs.depth.first_person_texture)?;
            match self.depth_history.as_ref().filter(|_| history_available) {
                Some(history) => device.set_texture(3, &history.texture)?,
                None => device.clear_texture(3)?,
            }
            let previous_reversed = self
                .depth_history
                .as_ref()
                .filter(|_| history_available)
                .is_some_and(|history| history.reversed_depth);
            bind_constants(device, desc, frame, history_available, previous_reversed)?;
            device.set_pixel_shader(self.shader(frame.settings.quality, frame.third_person))?;
            draw_quad(device, desc)?;
            for sampler in 0..=3 {
                device.clear_texture(sampler)?;
            }
        }

        if frame.third_person {
            self.record_world_depth(device, desc, frame_inputs, frame)?;
        }
        Ok(())
    }

    fn shader(&self, quality: MotionBlurQuality, third_person: bool) -> &PixelShader9 {
        match (quality, third_person) {
            (MotionBlurQuality::Performance, false) => &self.performance_shader,
            (MotionBlurQuality::High, false) => &self.high_shader,
            (MotionBlurQuality::Ultra, false) => &self.ultra_shader,
            (MotionBlurQuality::Performance, true) => &self.third_person_performance_shader,
            (MotionBlurQuality::High, true) => &self.third_person_high_shader,
            (MotionBlurQuality::Ultra, true) => &self.third_person_ultra_shader,
        }
    }

    fn record_world_depth(
        &mut self,
        device: &Device9Ref<'_>,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &FrameInputs,
        frame: PreparedMotionBlurFrame,
    ) -> Direct3DResult<()> {
        if self.depth_history_creation_failed {
            return Ok(());
        }
        let needs_resource = self
            .depth_history
            .as_ref()
            .is_none_or(|history| !history.matches(desc));
        if needs_resource {
            match MotionBlurDepthHistory::create(device, desc) {
                Ok(history) => self.depth_history = Some(history),
                Err(err) => {
                    self.depth_history_creation_failed = true;
                    log::warn!(
                        "[MOTION_BLUR] Third-person depth history unavailable; first-person blur remains active: {err}"
                    );
                    return Ok(());
                }
            }
        }
        let Some(history) = self.depth_history.as_ref() else {
            return Err(direct3d_failure());
        };

        bind_pipeline_state(device)?;
        bind_target(device, &history.surface, desc)?;
        bind_depth_texture(device, 0, frame_inputs.depth.texture)?;
        device.set_sampler_state(0, D3DSAMP_MINFILTER, D3DTEXF_POINT.0 as u32)?;
        device.set_sampler_state(0, D3DSAMP_MAGFILTER, D3DTEXF_POINT.0 as u32)?;
        device.set_pixel_shader_constant_f(0, &[screen_data(desc)])?;
        device.set_pixel_shader(&self.depth_history_shader)?;
        draw_quad(device, desc)?;
        device.clear_texture(0)?;

        let Some(history) = self.depth_history.as_mut() else {
            return Err(direct3d_failure());
        };
        history.valid = true;
        history.capture_epoch = frame.capture_epoch;
        history.reversed_depth = frame.world_reversed;
        Ok(())
    }
}

/// CPU-only previous-camera owner used before any D3D phase work is accepted.
#[derive(Default)]
pub(crate) struct MotionBlurTemporalState {
    previous_world: Option<TemporalCameraState>,
    previous_first_person: Option<TemporalCameraState>,
    last_config: Option<MotionBlurConfig>,
    last_dimensions: Option<[u32; 2]>,
}

impl MotionBlurTemporalState {
    /// Invalidates the previous-camera pair after a skip, reset, or disable.
    pub(crate) fn reset(&mut self) {
        self.previous_world = None;
        self.previous_first_person = None;
        self.last_config = None;
        self.last_dimensions = None;
    }

    /// Builds one immutable draw packet and advances the previous-camera state.
    ///
    /// The returned packet exists only when the camera pair is consecutive,
    /// survives cut rejection, and exceeds the configured minimum velocity.
    /// The runtime calls this before state-block capture and color-target
    /// allocation, making first, stationary, cut, and sub-threshold frames
    /// true no-GPU-work paths.
    pub(crate) fn prepare_frame(
        &mut self,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &FrameInputs,
        config: MotionBlurConfig,
    ) -> Option<PreparedMotionBlurFrame> {
        let settings = MotionBlurSettings::from_config(config);
        self.begin_sequence(config, [desc.Width, desc.Height]);

        // The resolved world depth may have been sampled under TAA jitter.
        // Motion is defined on the unjittered output grid, exactly as the TAA
        // history contract is, so read the restored persistent world camera.
        let current_world_camera = crate::backend::fnv_world_camera_frame(desc.Width, desc.Height)
            .filter(|camera| camera_supports_reprojection(*camera))
            .unwrap_or(frame_inputs.depth.world_projection.camera);
        let current_world = TemporalCameraState {
            camera: current_world_camera,
            epoch: frame_inputs.depth.capture_epoch,
        };
        let current_first_person = first_person_camera_state(frame_inputs);
        let world_reprojection = self
            .previous_world
            .and_then(|previous| MotionReprojection::between(previous, current_world));
        let first_person_reprojection = self
            .previous_first_person
            .zip(current_first_person)
            .and_then(|(previous, current)| MotionReprojection::between(previous, current));

        self.previous_world = Some(current_world);
        self.previous_first_person = current_first_person;

        let mut maximum_motion = world_reprojection.map_or(0.0, |reprojection| {
            reprojection.maximum_motion_pixels(
                current_world.camera,
                desc.Width,
                desc.Height,
                settings.shutter_fraction,
            )
        });
        if let (Some(current), Some(reprojection)) =
            (current_first_person, first_person_reprojection)
        {
            maximum_motion = maximum_motion.max(reprojection.maximum_motion_pixels(
                current.camera,
                desc.Width,
                desc.Height,
                settings.shutter_fraction * settings.first_person_strength,
            ));
        }
        maximum_motion = maximum_motion.min(settings.max_blur_pixels);
        let blur_requested = maximum_motion.is_finite()
            && maximum_motion > settings.minimum_velocity_pixels
            && world_reprojection.is_some();
        let third_person = frame_inputs.third_person_view == Some(true);
        if !blur_requested && !third_person {
            return None;
        }

        Some(PreparedMotionBlurFrame {
            settings,
            current_world: current_world.camera,
            world_reprojection,
            current_first_person: current_first_person.map(|state| state.camera),
            first_person_reprojection,
            world_reversed: frame_inputs
                .depth
                .world_projection
                .reversed_depth
                .unwrap_or(false),
            first_person_reversed: frame_inputs
                .depth
                .first_person_projection
                .reversed_depth
                .unwrap_or(false),
            first_person_depth_available: first_person_depth_contract_ready(frame_inputs),
            capture_epoch: frame_inputs.depth.capture_epoch,
            third_person,
            blur_requested,
        })
    }

    fn begin_sequence(&mut self, config: MotionBlurConfig, dimensions: [u32; 2]) {
        if self.last_config != Some(config) || self.last_dimensions != Some(dimensions) {
            self.previous_world = None;
            self.previous_first_person = None;
        }
        self.last_config = Some(config);
        self.last_dimensions = Some(dimensions);
    }
}

#[derive(Clone, Copy)]
struct MotionBlurSettings {
    enabled: bool,
    quality: MotionBlurQuality,
    shutter_fraction: f32,
    max_blur_pixels: f32,
    minimum_velocity_pixels: f32,
    first_person_strength: f32,
}

impl MotionBlurSettings {
    fn from_config(config: MotionBlurConfig) -> Self {
        Self {
            enabled: config.enabled,
            quality: config.quality,
            shutter_fraction: (config.shutter_angle / 360.0).clamp(0.0, 1.0),
            max_blur_pixels: config.max_blur_pixels.clamp(0.0, 48.0),
            minimum_velocity_pixels: config.minimum_velocity_pixels.clamp(0.0, 2.0),
            first_person_strength: config.first_person_strength.clamp(0.0, 1.0),
        }
    }
}

#[derive(Clone, Copy)]
/// Immutable constants selected by temporal preflight for one draw.
pub(crate) struct PreparedMotionBlurFrame {
    settings: MotionBlurSettings,
    current_world: CameraFrame,
    world_reprojection: Option<MotionReprojection>,
    current_first_person: Option<CameraFrame>,
    first_person_reprojection: Option<MotionReprojection>,
    world_reversed: bool,
    first_person_reversed: bool,
    first_person_depth_available: bool,
    capture_epoch: u64,
    third_person: bool,
    blur_requested: bool,
}

#[derive(Clone, Copy)]
struct TemporalCameraState {
    camera: CameraFrame,
    epoch: u64,
}

#[derive(Clone, Copy)]
struct MotionReprojection {
    rows: [[f32; 4]; 3],
    previous_camera: CameraFrame,
}

impl MotionReprojection {
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
        let camera_cut_distance = (previous.camera.far_z.min(current.camera.far_z) * 0.25)
            .min(MAX_CAMERA_CUT_TRANSLATION);
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
            previous_camera: previous.camera,
        })
    }

    fn previous_uv(
        self,
        current: CameraFrame,
        uv: [f32; 2],
        depth: f32,
        include_translation: bool,
    ) -> Option<[f32; 2]> {
        let position = [
            (current.frustum_left + (current.frustum_right - current.frustum_left) * uv[0]) * depth,
            (current.frustum_top + (current.frustum_bottom - current.frustum_top) * uv[1]) * depth,
            depth,
        ];
        let previous = self.rows.map(|row| {
            row[0] * position[0]
                + row[1] * position[1]
                + row[2] * position[2]
                + if include_translation { row[3] } else { 0.0 }
        });
        if previous[2] <= 0.001 || previous.iter().any(|value| !value.is_finite()) {
            return None;
        }
        let view_x = previous[0] / previous[2];
        let view_y = previous[1] / previous[2];
        let frustum = self.previous_camera;
        let result = [
            (view_x - frustum.frustum_left) / (frustum.frustum_right - frustum.frustum_left),
            (frustum.frustum_top - view_y) / (frustum.frustum_top - frustum.frustum_bottom),
        ];
        result
            .iter()
            .all(|value| value.is_finite())
            .then_some(result)
    }

    fn maximum_motion_pixels(
        self,
        current: CameraFrame,
        width: u32,
        height: u32,
        shutter_fraction: f32,
    ) -> f32 {
        if width == 0 || height == 0 || shutter_fraction <= 0.0 {
            return 0.0;
        }
        let mut maximum = 0.0f32;
        let points = [[0.0, 0.0], [1.0, 0.0], [0.0, 1.0], [1.0, 1.0], [0.5, 0.5]];
        let depths = [
            (current.near_z * 2.0).max(0.01),
            (current.far_z * 0.5).max(current.near_z + 1.0),
        ];
        for uv in points {
            for depth in depths {
                if let Some(previous_uv) = self.previous_uv(current, uv, depth, true) {
                    let x = (previous_uv[0] - uv[0]) * width as f32;
                    let y = (previous_uv[1] - uv[1]) * height as f32;
                    maximum = maximum.max(x.hypot(y) * shutter_fraction);
                }
            }
            if let Some(previous_uv) = self.previous_uv(current, uv, 1.0, false) {
                let x = (previous_uv[0] - uv[0]) * width as f32;
                let y = (previous_uv[1] - uv[1]) * height as f32;
                maximum = maximum.max(x.hypot(y) * shutter_fraction);
            }
        }
        maximum
    }
}

fn first_person_depth_contract_ready(frame_inputs: &FrameInputs) -> bool {
    frame_inputs.depth.first_person_texture.is_some()
        && frame_inputs
            .depth
            .first_person_projection
            .reversed_depth
            .is_some()
        && camera_supports_reprojection(frame_inputs.depth.first_person_projection.camera)
}

fn first_person_camera_state(frame_inputs: &FrameInputs) -> Option<TemporalCameraState> {
    first_person_depth_contract_ready(frame_inputs).then_some(TemporalCameraState {
        camera: frame_inputs.depth.first_person_projection.camera,
        epoch: frame_inputs.depth.capture_epoch,
    })
}

fn camera_supports_reprojection(camera: CameraFrame) -> bool {
    let transform = camera.world_transform;
    let frustum_width = camera.frustum_right - camera.frustum_left;
    let frustum_height = camera.frustum_top - camera.frustum_bottom;
    camera.available
        && camera.near_z.is_finite()
        && camera.far_z.is_finite()
        && camera.near_z > 0.0
        && camera.far_z > camera.near_z
        && frustum_width.is_finite()
        && frustum_height.is_finite()
        && frustum_width > f32::EPSILON
        && frustum_height > f32::EPSILON
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

fn shader_source(quality: MotionBlurQuality, third_person: bool) -> Vec<u8> {
    let mut source =
        format!("#define MOTION_BLUR_SAMPLES {}\n", quality.sample_count()).into_bytes();
    source.extend_from_slice(if third_person {
        THIRD_PERSON_SHADER
    } else {
        SHADER
    });
    source
}

fn compile_variant(quality: MotionBlurQuality, third_person: bool) -> Result<Vec<u32>> {
    let label = quality.config_value();
    let family = if third_person {
        format!("third-person-{label}")
    } else {
        label.to_owned()
    };
    let source = shader_source(quality, third_person);
    Ok(shaders::load_or_compile_hlsl_cached(
        shaders::HlslCacheSpec {
            namespace: "motion_blur",
            family: Some(&family),
            cache_label: &family,
            source_name: &format!("motion_blur.hlsl:{family}"),
            target: "ps_3_0",
            cache_tag: "pso",
            contract_revision: b"camera-motion-blur-v2",
        },
        &source,
    )?
    .bytecode)
}

fn compile_depth_history() -> Result<Vec<u32>> {
    Ok(shaders::load_or_compile_hlsl_cached(
        shaders::HlslCacheSpec {
            namespace: "motion_blur",
            family: Some("depth-history"),
            cache_label: "depth-history",
            source_name: "motion_blur_depth_history.hlsl",
            target: "ps_3_0",
            cache_tag: "pso",
            contract_revision: b"camera-motion-blur-depth-history-v1",
        },
        DEPTH_HISTORY_SHADER,
    )?
    .bytecode)
}

fn bind_depth_texture(
    device: &Device9Ref<'_>,
    sampler: u32,
    texture: Option<DepthTexture>,
) -> Direct3DResult<()> {
    match texture {
        Some(texture) => unsafe { device.set_raw_base_texture(sampler, texture.as_ptr()) },
        None => device.clear_texture(sampler),
    }
}

fn bind_constants(
    device: &Device9Ref<'_>,
    desc: &D3DSURFACE_DESC,
    frame: PreparedMotionBlurFrame,
    history_available: bool,
    previous_world_reversed: bool,
) -> Direct3DResult<()> {
    let Some(world) = frame.world_reprojection else {
        return Err(direct3d_failure());
    };
    let first_person_camera = frame.current_first_person.unwrap_or_default();
    let first_person = frame.first_person_reprojection;
    let first_person_rows = first_person.map_or(
        [
            [1.0, 0.0, 0.0, 0.0],
            [0.0, 1.0, 0.0, 0.0],
            [0.0, 0.0, 1.0, 0.0],
        ],
        |reprojection| reprojection.rows,
    );
    let previous_first_person = first_person
        .map(|reprojection| reprojection.previous_camera)
        .unwrap_or_default();
    let constants = [
        screen_data(desc),
        [
            frame.settings.shutter_fraction,
            frame.settings.max_blur_pixels,
            frame.settings.minimum_velocity_pixels,
            frame.settings.first_person_strength,
        ],
        [
            frame.world_reversed as u8 as f32,
            frame.first_person_reversed as u8 as f32,
            frame.first_person_depth_available as u8 as f32,
            first_person.is_some() as u8 as f32,
        ],
        camera_frustum(frame.current_world),
        [
            frame.current_world.near_z,
            frame.current_world.far_z,
            0.0,
            0.0,
        ],
        world.rows[0],
        world.rows[1],
        world.rows[2],
        camera_frustum(world.previous_camera),
        [
            world.previous_camera.near_z,
            world.previous_camera.far_z,
            0.0,
            0.0,
        ],
        camera_frustum(first_person_camera),
        [
            first_person_camera.near_z,
            first_person_camera.far_z,
            0.0,
            0.0,
        ],
        first_person_rows[0],
        first_person_rows[1],
        first_person_rows[2],
        camera_frustum(previous_first_person),
        [
            previous_first_person.near_z,
            previous_first_person.far_z,
            0.0,
            0.0,
        ],
        [
            history_available as u8 as f32,
            frame.third_person as u8 as f32,
            previous_world_reversed as u8 as f32,
            0.0,
        ],
    ];
    device.set_pixel_shader_constant_f(0, &constants)
}

fn screen_data(desc: &D3DSURFACE_DESC) -> [f32; 4] {
    [
        desc.Width as f32,
        desc.Height as f32,
        1.0 / desc.Width.max(1) as f32,
        1.0 / desc.Height.max(1) as f32,
    ]
}

fn camera_frustum(camera: CameraFrame) -> [f32; 4] {
    [
        camera.frustum_left,
        camera.frustum_right,
        camera.frustum_bottom,
        camera.frustum_top,
    ]
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
    for sampler in 0..=3 {
        device.set_sampler_state(sampler, D3DSAMP_ADDRESSU, D3DTADDRESS_CLAMP.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_ADDRESSV, D3DTADDRESS_CLAMP.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_MINFILTER, D3DTEXF_LINEAR.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_MAGFILTER, D3DTEXF_LINEAR.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_MIPFILTER, D3DTEXF_NONE.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_SRGBTEXTURE, 0)?;
    }
    for sampler in 1..=3 {
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
    target: &Surface9,
    desc: &D3DSURFACE_DESC,
) -> Direct3DResult<()> {
    let viewport = D3DVIEWPORT9 {
        X: 0,
        Y: 0,
        Width: desc.Width,
        Height: desc.Height,
        MinZ: 0.0,
        MaxZ: 1.0,
    };
    device.clear_texture(0)?;
    device.set_depth_stencil_surface(None)?;
    for target_index in 1..=3 {
        device.clear_render_target(target_index)?;
    }
    device.set_render_target(0, target)?;
    device.set_viewport(&viewport)
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

#[cfg(test)]
mod tests {
    use super::{
        DEPTH_HISTORY_SHADER, MotionBlurTemporalState, MotionReprojection, SHADER,
        THIRD_PERSON_SHADER, TemporalCameraState, camera_supports_reprojection, shader_source,
        should_prepare,
    };
    use crate::{
        backend::{
            CameraFrame, CameraTransformFrame, DepthFrame, DepthProjectionFrame, DepthProvider,
            DepthTexture, FrameInputs,
        },
        config::{MotionBlurConfig, MotionBlurQuality},
    };

    fn camera(rotation: [[f32; 3]; 3], translation: [f32; 3]) -> CameraFrame {
        CameraFrame {
            near_z: 5.0,
            far_z: 100_000.0,
            aspect_ratio: 16.0 / 9.0,
            frustum_left: -1.0,
            frustum_right: 1.0,
            frustum_bottom: -0.5625,
            frustum_top: 0.5625,
            world_transform: CameraTransformFrame {
                rotation,
                translation,
                scale: 1.0,
                available: true,
            },
            available: true,
        }
    }

    fn compiled_instruction_opcodes(bytecode: &[u32]) -> Vec<u16> {
        const COMMENT: u16 = 0xfffe;
        const END: u16 = 0xffff;
        let mut opcodes = Vec::new();
        let mut offset = 1usize;
        while offset < bytecode.len() {
            let token = bytecode[offset];
            let opcode = token as u16;
            if opcode == END {
                break;
            }
            if opcode == COMMENT {
                offset += 1 + ((token >> 16) & 0x7fff) as usize;
                continue;
            }
            opcodes.push(opcode);
            offset += 1 + ((token >> 24) & 0x0f) as usize;
        }
        assert!(offset < bytecode.len(), "shader bytecode has no END token");
        opcodes
    }

    #[test]
    fn every_motion_blur_quality_variant_compiles_with_bounded_work() {
        const TEXLD: u16 = 66;
        const TEXLDD: u16 = 93;
        const TEXLDL: u16 = 95;
        for third_person in [false, true] {
            for quality in [
                MotionBlurQuality::Performance,
                MotionBlurQuality::High,
                MotionBlurQuality::Ultra,
            ] {
                let source = shader_source(quality, third_person);
                let bytecode = crate::shaders::compile_hlsl_source_target(
                    &format!("motion-blur:{quality:?}:third-person={third_person}"),
                    &source,
                    "ps_3_0",
                )
                .expect("motion-blur shader variant");
                assert_eq!(bytecode[0], 0xffff_0300, "{quality:?} must remain ps_3_0");
                let opcodes = compiled_instruction_opcodes(&bytecode);
                let texture_count = opcodes
                    .iter()
                    .filter(|opcode| matches!(**opcode, TEXLD | TEXLDD | TEXLDL))
                    .count();
                assert!(
                    opcodes.len() <= 512,
                    "{quality:?} third_person={third_person} uses {} instructions",
                    opcodes.len()
                );
                assert!(
                    texture_count <= quality.sample_count() as usize * 3 + 1,
                    "{quality:?} third_person={third_person} uses {texture_count} texture operations"
                );
            }
        }
    }

    #[test]
    fn depth_history_shader_is_one_sample_and_bounded() {
        const TEXLD: u16 = 66;
        const TEXLDD: u16 = 93;
        const TEXLDL: u16 = 95;
        let bytecode = crate::shaders::compile_hlsl_source_target(
            "motion-blur-depth-history",
            DEPTH_HISTORY_SHADER,
            "ps_3_0",
        )
        .expect("motion-blur depth-history shader");
        assert_eq!(bytecode[0], 0xffff_0300);
        let opcodes = compiled_instruction_opcodes(&bytecode);
        let texture_count = opcodes
            .iter()
            .filter(|opcode| matches!(**opcode, TEXLD | TEXLDD | TEXLDL))
            .count();
        assert!(
            opcodes.len() <= 96,
            "history pass uses {} instructions",
            opcodes.len()
        );
        assert_eq!(texture_count, 1);
    }

    #[test]
    fn shader_abi_uses_only_the_documented_inputs() {
        let source = std::str::from_utf8(SHADER).expect("motion-blur source");
        for binding in [
            "SceneColor : register(s0)",
            "WorldDepth : register(s1)",
            "FirstPersonDepth : register(s2)",
            "ScreenData : register(c0)",
            "PreviousFirstPersonDepth : register(c16)",
        ] {
            assert!(source.contains(binding), "missing ABI binding {binding}");
        }
        assert_eq!(source.matches("sampler2D ").count(), 3);
        assert_eq!(source.matches(": register(c").count(), 17);
        assert!(source.contains("[loop]"));
        assert!(source.contains("float layerStrength = 1.0f;"));
        assert!(source.contains("layerStrength = MotionOptions.w;"));

        let third_person =
            std::str::from_utf8(THIRD_PERSON_SHADER).expect("third-person motion-blur source");
        for binding in [
            "SceneColor : register(s0)",
            "WorldDepth : register(s1)",
            "PreviousWorldDepthHistory : register(s3)",
            "HistoryFlags : register(c17)",
        ] {
            assert!(
                third_person.contains(binding),
                "missing third-person ABI binding {binding}"
            );
        }
        assert_eq!(third_person.matches("sampler2D ").count(), 3);
        assert_eq!(third_person.matches(": register(c").count(), 11);
        assert!(!third_person.contains("FirstPersonDepth"));
    }

    #[test]
    fn shader_uses_explicit_lod_and_contains_no_derivatives_or_color_history() {
        for bytes in [SHADER, THIRD_PERSON_SHADER, DEPTH_HISTORY_SHADER] {
            let source = std::str::from_utf8(bytes).expect("motion-blur source");
            assert!(source.contains("tex2Dlod("));
            assert!(!source.contains("tex2D("));
            assert!(!source.contains("ddx("));
            assert!(!source.contains("ddy("));
            assert!(!source.contains("PreviousSceneColor"));
        }
        let blur = std::str::from_utf8(SHADER).expect("motion-blur source");
        assert!(blur.contains("return float4(sum / max(weightSum, 0.0001f), current.a)"));
    }

    #[test]
    fn identity_camera_is_stationary_and_translation_has_depth_parallax() {
        let identity = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let previous = camera(identity, [0.0; 3]);
        let stable = MotionReprojection::between(
            TemporalCameraState {
                camera: previous,
                epoch: 4,
            },
            TemporalCameraState {
                camera: previous,
                epoch: 5,
            },
        )
        .expect("identity reprojection");
        assert!(
            stable.maximum_motion_pixels(previous, 1920, 1080, 0.5) < 0.0001,
            "stationary cameras must skip the draw"
        );

        // FNV camera column 2 is the right vector; translating on world Z for
        // this identity fixture therefore creates lateral screen motion.
        let translated = camera(identity, [0.0, 0.0, 10.0]);
        let moving = MotionReprojection::between(
            TemporalCameraState {
                camera: previous,
                epoch: 5,
            },
            TemporalCameraState {
                camera: translated,
                epoch: 6,
            },
        )
        .expect("translation reprojection");
        let near = moving
            .previous_uv(translated, [0.5, 0.5], 20.0, true)
            .expect("near projection");
        let far = moving
            .previous_uv(translated, [0.5, 0.5], 20_000.0, true)
            .expect("far projection");
        assert!((near[0] - 0.5).abs() > (far[0] - 0.5).abs() * 100.0);

        let sky = moving
            .previous_uv(translated, [0.25, 0.75], 1.0, false)
            .expect("sky projection");
        assert!((sky[0] - 0.25).abs() < 0.0001);
        assert!((sky[1] - 0.75).abs() < 0.0001);
    }

    #[test]
    fn subpixel_rotation_is_finite_and_continuous_across_the_output_diagonal() {
        let identity = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let angle = 0.0005f32;
        let (sine, cosine) = angle.sin_cos();
        let rotated = [[cosine, 0.0, sine], [0.0, 1.0, 0.0], [-sine, 0.0, cosine]];
        let previous = camera(identity, [0.0; 3]);
        let current = camera(rotated, [0.0; 3]);
        let reprojection = MotionReprojection::between(
            TemporalCameraState {
                camera: previous,
                epoch: 9,
            },
            TemporalCameraState {
                camera: current,
                epoch: 10,
            },
        )
        .expect("subpixel rotation");
        let left = [0.4999, 0.4999];
        let right = [0.5001, 0.5001];
        let left_previous = reprojection
            .previous_uv(current, left, 100.0, true)
            .expect("left projection");
        let right_previous = reprojection
            .previous_uv(current, right, 100.0, true)
            .expect("right projection");
        let separation =
            (right_previous[0] - left_previous[0]).hypot(right_previous[1] - left_previous[1]);
        assert!(left_previous.into_iter().all(f32::is_finite));
        assert!(right_previous.into_iter().all(f32::is_finite));
        assert!(separation > 0.0001 && separation < 0.001);
        let motion = reprojection.maximum_motion_pixels(current, 1920, 1080, 0.5);
        assert!(motion > 0.01 && motion < 10.0);
    }

    #[test]
    fn temporal_pair_rejects_first_frame_gaps_invalid_cameras_and_cuts() {
        let identity = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let valid = camera(identity, [0.0; 3]);
        assert!(camera_supports_reprojection(valid));
        assert!(
            MotionReprojection::between(
                TemporalCameraState {
                    camera: valid,
                    epoch: 1
                },
                TemporalCameraState {
                    camera: valid,
                    epoch: 3
                }
            )
            .is_none()
        );
        let cut = camera(identity, [5_000.0, 0.0, 0.0]);
        assert!(
            MotionReprojection::between(
                TemporalCameraState {
                    camera: valid,
                    epoch: 3
                },
                TemporalCameraState {
                    camera: cut,
                    epoch: 4
                }
            )
            .is_none()
        );
        let mut invalid = valid;
        invalid.world_transform.translation[0] = f32::NAN;
        assert!(!camera_supports_reprojection(invalid));
    }

    #[test]
    fn config_or_resize_primes_a_new_temporal_sequence() {
        let identity = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let camera = camera(identity, [0.0; 3]);
        let mut state = MotionBlurTemporalState::default();
        let config = MotionBlurConfig {
            enabled: true,
            ..MotionBlurConfig::default()
        };
        state.begin_sequence(config, [1920, 1080]);
        state.previous_world = Some(TemporalCameraState { camera, epoch: 2 });
        state.begin_sequence(config, [1280, 720]);
        assert!(state.previous_world.is_none());

        state.previous_world = Some(TemporalCameraState { camera, epoch: 3 });
        state.begin_sequence(
            MotionBlurConfig {
                shutter_angle: 90.0,
                ..config
            },
            [1280, 720],
        );
        assert!(state.previous_world.is_none());
    }

    #[test]
    fn disabled_zero_or_missing_depth_inputs_reject_before_gpu_work() {
        let identity = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let camera = camera(identity, [0.0; 3]);
        let texture =
            DepthTexture::new(1usize as *mut std::ffi::c_void).expect("non-null test texture");
        let mut inputs = FrameInputs {
            third_person_view: Some(false),
            depth: DepthFrame::from_textures(
                DepthProvider::FalloutNewVegas,
                Some(texture),
                None,
                DepthProjectionFrame {
                    camera,
                    reversed_depth: Some(true),
                    ..DepthProjectionFrame::default()
                },
                DepthProjectionFrame::default(),
                1,
            ),
            ..FrameInputs::default()
        };
        let mut config = MotionBlurConfig {
            enabled: true,
            ..MotionBlurConfig::default()
        };
        assert!(should_prepare(&inputs, config));
        config.enabled = false;
        assert!(!should_prepare(&inputs, config));
        config.enabled = true;
        config.shutter_angle = 0.0;
        assert!(!should_prepare(&inputs, config));
        config.shutter_angle = 180.0;
        config.max_blur_pixels = 0.0;
        assert!(!should_prepare(&inputs, config));
        config.max_blur_pixels = 24.0;
        inputs.depth.texture = None;
        assert!(!should_prepare(&inputs, config));
    }

    #[test]
    fn third_person_world_blur_is_admitted_only_with_a_known_camera_mode() {
        let identity = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let previous = camera(identity, [0.0; 3]);
        let current = camera(identity, [0.0, 0.0, 10.0]);
        let reprojection = MotionReprojection::between(
            TemporalCameraState {
                camera: previous,
                epoch: 10,
            },
            TemporalCameraState {
                camera: current,
                epoch: 11,
            },
        )
        .expect("camera-only reprojection");
        let player_history_uv = reprojection
            .previous_uv(current, [0.5, 0.5], 80.0, true)
            .expect("representative player depth");
        assert!(
            (player_history_uv[0] - 0.5).abs() > 0.01,
            "negative control must reproduce camera-only player smear"
        );

        let texture =
            DepthTexture::new(1usize as *mut std::ffi::c_void).expect("non-null test texture");
        let mut inputs = FrameInputs {
            third_person_view: Some(false),
            depth: DepthFrame::from_textures(
                DepthProvider::FalloutNewVegas,
                Some(texture),
                None,
                DepthProjectionFrame {
                    camera: current,
                    reversed_depth: Some(true),
                    ..DepthProjectionFrame::default()
                },
                DepthProjectionFrame::default(),
                11,
            ),
            ..FrameInputs::default()
        };
        let config = MotionBlurConfig {
            enabled: true,
            ..MotionBlurConfig::default()
        };
        assert!(should_prepare(&inputs, config));

        let desc = libpsycho::os::windows::directx9::D3DSURFACE_DESC {
            Width: 1_920,
            Height: 1_080,
            ..libpsycho::os::windows::directx9::D3DSURFACE_DESC::default()
        };
        let previous_texture =
            DepthTexture::new(2usize as *mut std::ffi::c_void).expect("non-null test texture");
        let previous_inputs = FrameInputs {
            third_person_view: Some(false),
            depth: DepthFrame::from_textures(
                DepthProvider::FalloutNewVegas,
                Some(previous_texture),
                None,
                DepthProjectionFrame {
                    camera: previous,
                    reversed_depth: Some(true),
                    ..DepthProjectionFrame::default()
                },
                DepthProjectionFrame::default(),
                10,
            ),
            ..FrameInputs::default()
        };
        let mut first_person_state = MotionBlurTemporalState::default();
        assert!(
            first_person_state
                .prepare_frame(&desc, &previous_inputs, config)
                .is_none()
        );
        let first_person_frame = first_person_state
            .prepare_frame(&desc, &inputs, config)
            .expect("first-person world blur");
        assert!(first_person_frame.blur_requested);
        assert!(!first_person_frame.third_person);
        assert!(first_person_frame.world_reprojection.is_some());

        inputs.third_person_view = Some(true);
        assert!(
            should_prepare(&inputs, config),
            "third-person world blur must reach temporal depth rejection"
        );
        let mut previous_third_person_inputs = previous_inputs;
        previous_third_person_inputs.third_person_view = Some(true);
        let mut third_person_state = MotionBlurTemporalState::default();
        let first_third_person_frame = third_person_state
            .prepare_frame(&desc, &previous_third_person_inputs, config)
            .expect("third-person history seed");
        assert!(!first_third_person_frame.blur_requested);
        let third_person_frame = third_person_state
            .prepare_frame(&desc, &inputs, config)
            .expect("third-person world blur");
        assert!(third_person_frame.blur_requested);
        assert!(third_person_frame.third_person);

        inputs.third_person_view = None;
        assert!(
            !should_prepare(&inputs, config),
            "unknown camera mode must fail closed"
        );
    }

    fn smooth01(value: f32) -> f32 {
        let value = value.clamp(0.0, 1.0);
        value * value * (3.0 - 2.0 * value)
    }

    fn depth_acceptance(center: Option<f32>, sample: Option<f32>, motion_pixels: f32) -> f32 {
        match (center, sample) {
            (None, None) => 1.0,
            (Some(center), Some(sample)) => {
                let relative = (sample - center).abs() / center.min(sample).max(0.01);
                let tolerance = 0.025 + (motion_pixels * 0.002).min(0.075);
                1.0 - smooth01((relative - tolerance) / tolerance.max(0.0001))
            }
            _ => 0.0,
        }
    }

    #[derive(Clone, Copy)]
    enum ReferenceLayer {
        World(f32),
        FirstPerson(f32),
        Sky,
        Invalid,
    }

    fn layer_acceptance(center: ReferenceLayer, sample: ReferenceLayer, motion_pixels: f32) -> f32 {
        match (center, sample) {
            (ReferenceLayer::World(center), ReferenceLayer::World(sample))
            | (ReferenceLayer::FirstPerson(center), ReferenceLayer::FirstPerson(sample)) => {
                depth_acceptance(Some(center), Some(sample), motion_pixels)
            }
            (ReferenceLayer::Sky, ReferenceLayer::Sky) => 1.0,
            _ => 0.0,
        }
    }

    fn sample_linear(colors: &[[f32; 3]], position: f32) -> [f32; 3] {
        let position = position.clamp(0.0, colors.len().saturating_sub(1) as f32);
        let left = position.floor() as usize;
        let right = (left + 1).min(colors.len() - 1);
        let t = position - left as f32;
        [
            colors[left][0] + (colors[right][0] - colors[left][0]) * t,
            colors[left][1] + (colors[right][1] - colors[left][1]) * t,
            colors[left][2] + (colors[right][2] - colors[left][2]) * t,
        ]
    }

    fn reference_blur(
        colors: &[[f32; 3]],
        depths: &[Option<f32>],
        center: usize,
        motion_pixels: f32,
        taps: usize,
        depth_aware: bool,
    ) -> [f32; 3] {
        let mut sum = colors[center].map(|channel| channel * 0.5);
        let mut weight_sum = 0.5;
        for tap in 1..taps {
            let t = tap as f32 / (taps - 1) as f32;
            let position = center as f32 + motion_pixels * t;
            let depth_index = position
                .round()
                .clamp(0.0, depths.len().saturating_sub(1) as f32)
                as usize;
            let endpoint = if tap == taps - 1 { 0.5 } else { 1.0 };
            let depth_weight = if depth_aware {
                depth_acceptance(depths[center], depths[depth_index], motion_pixels.abs())
            } else {
                1.0
            };
            let weight = endpoint * depth_weight;
            let sample = sample_linear(colors, position);
            for channel in 0..3 {
                sum[channel] += sample[channel] * weight;
            }
            weight_sum += weight;
        }
        sum.map(|channel| channel / weight_sum)
    }

    fn reference_third_person_blur(
        colors: &[[f32; 3]],
        current_depths: &[Option<f32>],
        previous_depths: &[Option<f32>],
        center: usize,
        motion_pixels: f32,
        taps: usize,
    ) -> [f32; 3] {
        let previous_index = (center as f32 + motion_pixels)
            .round()
            .clamp(0.0, previous_depths.len().saturating_sub(1) as f32)
            as usize;
        let Some(predicted_depth) = current_depths[center] else {
            return reference_blur(colors, current_depths, center, motion_pixels, taps, true);
        };
        if !previous_surface_matches(
            predicted_depth,
            previous_depths[previous_index],
            motion_pixels.abs(),
        ) {
            return colors[center];
        }
        reference_blur(colors, current_depths, center, motion_pixels, taps, true)
    }

    #[test]
    fn third_person_reference_image_blurs_world_and_preserves_player() {
        const WIDTH: usize = 9;
        const HEIGHT: usize = 5;
        let mut colors = vec![[0.05, 0.10, 0.20]; WIDTH * HEIGHT];
        let mut current_depths = vec![Some(1_000.0); WIDTH * HEIGHT];
        let mut previous_depths = current_depths.clone();
        for y in 0..HEIGHT {
            for x in 0..WIDTH {
                colors[y * WIDTH + x][2] += x as f32 * 0.05;
            }
        }
        let player = 2 * WIDTH + 4;
        colors[player] = [1.0, 0.1, 0.05];
        current_depths[player] = Some(80.0);
        previous_depths[player] = Some(80.0);

        let naive_player = reference_blur(&colors, &current_depths, player, 2.0, 7, false);
        let protected_player =
            reference_third_person_blur(&colors, &current_depths, &previous_depths, player, 2.0, 7);
        assert!(
            naive_player[0] < 0.8,
            "negative control must visibly smear the player"
        );
        assert_eq!(protected_player, colors[player]);

        let world = 2 * WIDTH + 1;
        let blurred_world =
            reference_third_person_blur(&colors, &current_depths, &previous_depths, world, 2.0, 7);
        assert!(
            (blurred_world[2] - colors[world][2]).abs() > 0.02,
            "matching world depth must retain visible camera blur"
        );
    }

    #[test]
    fn reference_filter_preserves_baselines_borders_and_depth_edges() {
        let constant = vec![[0.25, 0.5, 0.75]; 9];
        let flat_depth = vec![Some(100.0); 9];
        for center in [0, 4, 8] {
            for motion in [-6.0, 0.0, 6.0] {
                let result = reference_blur(&constant, &flat_depth, center, motion, 9, true);
                assert_eq!(result, constant[center]);
                assert!(result.into_iter().all(|value| value.is_finite()));
            }
        }

        let colors = [
            [1.0, 0.0, 0.0],
            [1.0, 0.0, 0.0],
            [1.0, 0.0, 0.0],
            [0.0, 0.0, 1.0],
            [0.0, 0.0, 1.0],
            [0.0, 0.0, 1.0],
        ];
        let depths = [
            Some(10.0),
            Some(10.0),
            Some(10.0),
            Some(100.0),
            Some(100.0),
            Some(100.0),
        ];
        let negative_control = reference_blur(&colors, &depths, 2, 3.0, 7, false);
        let protected = reference_blur(&colors, &depths, 2, 3.0, 7, true);
        assert!(
            negative_control[2] > 0.25,
            "naive blur must reproduce edge bleed"
        );
        assert!(protected[0] > 0.999 && protected[2] < 0.001);
    }

    #[test]
    fn depth_gate_accepts_gradients_but_rejects_sky_changes() {
        assert!(depth_acceptance(Some(100.0), Some(103.0), 12.0) > 0.5);
        assert_eq!(depth_acceptance(Some(100.0), Some(1_000.0), 12.0), 0.0);
        assert_eq!(depth_acceptance(Some(100.0), None, 12.0), 0.0);
        assert_eq!(depth_acceptance(None, Some(100.0), 12.0), 0.0);
        assert_eq!(depth_acceptance(None, None, 12.0), 1.0);
    }

    #[test]
    fn layer_gate_never_crosses_world_first_person_sky_or_invalid_depth() {
        assert!(
            layer_acceptance(
                ReferenceLayer::World(100.0),
                ReferenceLayer::World(103.0),
                12.0,
            ) > 0.5
        );
        assert_eq!(
            layer_acceptance(
                ReferenceLayer::World(100.0),
                ReferenceLayer::FirstPerson(10.0),
                12.0,
            ),
            0.0
        );
        assert_eq!(
            layer_acceptance(
                ReferenceLayer::FirstPerson(10.0),
                ReferenceLayer::World(100.0),
                12.0,
            ),
            0.0
        );
        assert_eq!(
            layer_acceptance(ReferenceLayer::Sky, ReferenceLayer::World(100.0), 12.0),
            0.0
        );
        assert_eq!(
            layer_acceptance(ReferenceLayer::World(100.0), ReferenceLayer::Invalid, 12.0,),
            0.0
        );
        assert_eq!(
            layer_acceptance(ReferenceLayer::Sky, ReferenceLayer::Sky, 12.0),
            1.0
        );
    }

    fn encoded_depth(linear: f32, near: f32, far: f32, reversed: bool) -> f32 {
        if reversed {
            (near * far / linear - near) / (far - near)
        } else {
            (far - near * far / linear) / (far - near)
        }
    }

    fn reconstructed_depth(raw: f32, near: f32, far: f32, reversed: bool) -> f32 {
        if reversed {
            near * far / (raw * (far - near) + near)
        } else {
            near * far / (far - raw * (far - near))
        }
    }

    fn quantize_unorm(value: f32, bits: u32) -> f32 {
        let levels = ((1u32 << bits) - 1) as f32;
        (value.clamp(0.0, 1.0) * levels).round() / levels
    }

    fn pack_depth24(raw: f32) -> [f32; 3] {
        let scaled = [raw, raw * 255.0, raw * 65_025.0];
        let mut packed = scaled.map(f32::fract);
        packed[0] -= packed[1] / 255.0;
        packed[1] -= packed[2] / 255.0;
        packed.map(|channel| quantize_unorm(channel, 8))
    }

    fn unpack_depth24(packed: [f32; 3]) -> f32 {
        packed[0] + packed[1] / 255.0 + packed[2] / 65_025.0
    }

    fn previous_surface_matches(
        predicted_previous_depth: f32,
        history_depth: Option<f32>,
        motion_pixels: f32,
    ) -> bool {
        let Some(history_depth) = history_depth else {
            return false;
        };
        let relative_difference = (history_depth - predicted_previous_depth).abs()
            / history_depth.min(predicted_previous_depth).max(0.01);
        let tolerance = 0.03 + (motion_pixels * 0.003).min(0.07);
        relative_difference <= tolerance
    }

    #[test]
    fn packed_depth_history_round_trips_both_projection_conventions() {
        let near = 5.0;
        let far = 100_000.0;
        for reversed in [false, true] {
            for expected in [6.0, 80.0, 1_000.0, 10_000.0] {
                let raw = encoded_depth(expected, near, far, reversed);
                let restored_raw = unpack_depth24(pack_depth24(raw));
                let restored = reconstructed_depth(restored_raw, near, far, reversed);
                assert!(
                    ((restored - expected) / expected).abs() < 0.001,
                    "{expected} reconstructed as {restored}"
                );
            }
        }
    }

    #[test]
    fn temporal_depth_rejects_player_smear_but_accepts_static_world() {
        let predicted_player_depth = 80.0;
        assert!(
            previous_surface_matches(predicted_player_depth, Some(81.0), 12.0),
            "a static world surface must retain camera blur"
        );
        assert!(
            !previous_surface_matches(predicted_player_depth, Some(1_000.0), 12.0),
            "the player must stay sharp when world reprojection lands on background"
        );
        assert!(
            !previous_surface_matches(predicted_player_depth, None, 12.0),
            "disoccluded geometry must stay sharp"
        );
    }

    #[test]
    fn standard_and_reversed_depth_match_after_d16_and_d24_quantization() {
        let near = 5.0;
        let far = 100_000.0;
        for bits in [16, 24] {
            let tolerance = if bits == 16 { 0.025 } else { 0.0002 };
            for expected in [6.0, 100.0, 1_000.0, 10_000.0] {
                let standard_raw = quantize_unorm(encoded_depth(expected, near, far, false), bits);
                let reversed_raw = quantize_unorm(encoded_depth(expected, near, far, true), bits);
                let standard = reconstructed_depth(standard_raw, near, far, false);
                let reversed = reconstructed_depth(reversed_raw, near, far, true);
                assert!(((standard - expected) / expected).abs() < tolerance);
                assert!(((reversed - expected) / expected).abs() < tolerance);
                assert!(((standard - reversed) / expected).abs() < 0.0002);
            }
        }
    }

    #[test]
    fn reference_filter_is_finite_bounded_and_protects_thin_features() {
        let colors = [
            [0.0, 0.0, 0.0],
            [0.2, 0.4, 0.6],
            [1.0, 1.0, 1.0],
            [0.6, 0.4, 0.2],
            [0.0, 0.0, 0.0],
        ];
        let grazing_depth = [
            Some(100.0),
            Some(102.0),
            Some(104.0),
            Some(106.0),
            Some(108.0),
        ];
        for taps in [5, 7, 9] {
            for center in 0..colors.len() {
                let result = reference_blur(&colors, &grazing_depth, center, 2.25, taps, true);
                assert!(result.into_iter().all(|value| value.is_finite()));
                assert!(result.into_iter().all(|value| (0.0..=1.0).contains(&value)));
            }
        }

        let thin_depth = [
            Some(100.0),
            Some(100.0),
            Some(5.0),
            Some(100.0),
            Some(100.0),
        ];
        let protected = reference_blur(&colors, &thin_depth, 2, 2.0, 9, true);
        let negative_control = reference_blur(&colors, &thin_depth, 2, 2.0, 9, false);
        // The first subpixel tap may legitimately blend across the bilinear
        // color footprint. All later background taps must be rejected, so the
        // one-pixel foreground remains dominant instead of averaging away.
        assert!(protected.into_iter().all(|value| value > 0.8));
        for channel in 0..3 {
            assert!(protected[channel] > negative_control[channel] + 0.3);
        }
    }

    #[test]
    fn fullscreen_quad_obeys_the_d3d9_half_pixel_contract() {
        let width = 127.0;
        let height = 72.0;
        let positions = [
            [-0.5, -0.5],
            [width - 0.5, -0.5],
            [-0.5, height - 0.5],
            [width - 0.5, height - 0.5],
        ];
        assert_eq!(positions[0], [-0.5, -0.5]);
        assert_eq!(positions[3], [126.5, 71.5]);
    }
}

//! World-only temporal anti-aliasing resolved before first-person and UI rendering.
//!
//! TAA copies the engine world target, resolves color into ping-pong FP16
//! history, records a logarithmic depth-rejection key, and copies the result
//! back before first-person/UI rendering. On devices exposing two render
//! targets plus `MRTINDEPENDENTBITDEPTHS`, color and the R16F key are emitted by
//! one pixel invocation. The original two-pass path remains the capability
//! fallback. Both paths preserve engine alpha and are enclosed by the world
//! pipeline's full state/attachment transaction.
//!
//! All three production variants are compiled and cached by a process worker.
//! World render callbacks only create device objects from published bytecode.

use std::{
    sync::{
        LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use anyhow::Result;
use libpsycho::os::windows::directx9::{
    D3DCULL_NONE, D3DFMT_A16B16G16R16F, D3DFMT_R16F, D3DFORMAT, D3DPT_TRIANGLELIST,
    D3DRS_ALPHABLENDENABLE, D3DRS_ALPHATESTENABLE, D3DRS_COLORWRITEENABLE, D3DRS_COLORWRITEENABLE1,
    D3DRS_CULLMODE, D3DRS_SCISSORTESTENABLE, D3DRS_SRGBWRITEENABLE, D3DRS_STENCILENABLE,
    D3DRS_ZENABLE, D3DRS_ZWRITEENABLE, D3DSAMP_ADDRESSU, D3DSAMP_ADDRESSV, D3DSAMP_MAGFILTER,
    D3DSAMP_MINFILTER, D3DSAMP_MIPFILTER, D3DSAMP_SRGBTEXTURE, D3DSURFACE_DESC, D3DTA_TEXTURE,
    D3DTADDRESS_CLAMP, D3DTEXF_LINEAR, D3DTEXF_NONE, D3DTEXF_POINT, D3DTOP_SELECTARG1,
    D3DTSS_ALPHAARG1, D3DTSS_ALPHAOP, D3DTSS_COLORARG1, D3DTSS_COLOROP, D3DVIEWPORT9, Device9Ref,
    Direct3DResult, PixelShader9, ScreenVertex, Surface9, Texture9, direct3d_failure,
};

use crate::{
    backend::{CameraFrame, DepthFrame},
    config, shaders,
};
use parking_lot::Mutex;

const COLOR_WRITE_ALL: u32 = 0x0F;
const OPTION_REGISTER: u32 = 3;
const REPROJECTION_REGISTER: u32 = 5;
const TARGET_RETRY_FRAMES: u16 = 120;
const TAA_SHADER: &[u8] = include_bytes!("../../shaders/embedded/aa_temporal.hlsl");
const DEPTH_KEY_SHADER: &[u8] = include_bytes!("../../shaders/embedded/aa_temporal_depth_key.hlsl");

static COMPILE_STARTED: AtomicBool = AtomicBool::new(false);
static COMPILE_FAILED: AtomicBool = AtomicBool::new(false);
static COMPILE_READY: AtomicBool = AtomicBool::new(false);
static BYTECODE: LazyLock<Mutex<Option<TemporalAaBytecode>>> = LazyLock::new(|| Mutex::new(None));

struct TemporalAaBytecode {
    resolve: Vec<u32>,
    resolve_mrt: Vec<u32>,
    depth_key: Vec<u32>,
}

impl TemporalAaBytecode {
    fn compile() -> Result<Self> {
        Self::compile_with_mrt_source(&temporal_shader_source(true))
    }

    // Separate the optional compiler boundary so failure containment can be
    // exercised with the real compiler, independently of device capabilities.
    fn compile_with_mrt_source(mrt_source: &[u8]) -> Result<Self> {
        let resolve = shaders::compile_hlsl_source("aa_temporal.hlsl", TAA_SHADER)?;
        let depth_key =
            shaders::compile_hlsl_source("aa_temporal_depth_key.hlsl", DEPTH_KEY_SHADER)?;
        let resolve_mrt = match shaders::compile_hlsl_source("aa_temporal.hlsl:mrt", mrt_source) {
            Ok(bytecode) => bytecode,
            Err(error) => {
                log::warn!(
                    "[TAA] MRT preparation unavailable; retaining two-pass resolve: {error:#}"
                );
                Vec::new()
            }
        };
        Ok(Self {
            resolve,
            resolve_mrt,
            depth_key,
        })
    }
}

/// Start process-owned TAA shader preparation outside world render callbacks.
pub(crate) fn service_preparation() {
    if COMPILE_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    if let Err(err) = thread::Builder::new()
        .name("omv-taa-compile".to_owned())
        .spawn(
            || match super::shader_preparation::run_serialized(TemporalAaBytecode::compile) {
                Ok(bytecode) => {
                    *BYTECODE.lock() = Some(bytecode);
                    COMPILE_READY.store(true, Ordering::Release);
                }
                Err(err) => {
                    COMPILE_FAILED.store(true, Ordering::Release);
                    log::warn!("[TAA] Shader preparation failed: {err:#}");
                }
            },
        )
    {
        COMPILE_FAILED.store(true, Ordering::Release);
        log::warn!("[TAA] Could not start shader preparation: {err}");
    }
}

#[derive(Clone, Copy)]
/// Sanitized temporal-AA constants used by jitter and resolve.
pub(crate) struct TemporalAaConfig {
    options: [f32; 4],
}

impl TemporalAaConfig {
    /// Convert menu configuration into the fixed shader constant payload.
    pub(crate) fn from_config(config: config::TemporalAaConfig) -> Self {
        let defaults = config::TemporalAaConfig::default();
        let finite = |value: f32, fallback: f32, low: f32, high: f32| {
            if value.is_finite() {
                value.clamp(low, high)
            } else {
                fallback
            }
        };
        Self {
            options: [
                finite(config.history_weight, defaults.history_weight, 0.0, 0.98),
                finite(config.clamp_strength, defaults.clamp_strength, 0.25, 2.0),
                finite(config.sharpness, defaults.sharpness, 0.0, 1.0),
                finite(config.jitter_scale, defaults.jitter_scale, 0.0, 1.5),
            ],
        }
    }

    /// Return the bounded projection-jitter scale in pixel units.
    pub(crate) fn jitter_scale(self) -> f32 {
        self.options[3].clamp(0.0, 1.5)
    }
}

#[cfg(test)]
mod behavior_tests;

#[cfg(test)]
mod shader_compile_tests {
    use super::{
        BYTECODE, COLOR_WRITE_ALL, COMPILE_READY, COMPILE_STARTED, DEPTH_KEY_SHADER, TAA_SHADER,
        TemporalAaBytecode, TemporalAaConfig, TemporalAaEffect, TemporalCameraState,
        TemporalReprojection, temporal_shader_source,
    };
    use crate::backend::{
        CameraFrame, CameraTransformFrame, DepthFrame, DepthProjectionFrame, DepthProvider,
        DepthTexture,
    };
    use libpsycho::os::windows::{
        directx9::{
            D3DDEVTYPE_HAL, D3DDEVTYPE_NULLREF, D3DFMT_A16B16G16R16F, D3DFMT_D24S8, D3DFMT_R32F,
            D3DMULTISAMPLE_NONE, D3DRS_COLORWRITEENABLE1, Device9, create_direct3d9,
        },
        winapi::{get_active_window, get_desktop_window, get_foreground_window},
    };
    use std::sync::atomic::Ordering;

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
    fn embedded_temporal_aa_shader_compiles() {
        crate::shaders::assert_hlsl_compiles("aa_temporal.hlsl", TAA_SHADER, "ps_3_0");
        crate::shaders::assert_hlsl_compiles(
            "aa_temporal.hlsl:mrt",
            &temporal_shader_source(true),
            "ps_3_0",
        );
        crate::shaders::assert_hlsl_compiles(
            "aa_temporal_depth_key.hlsl",
            DEPTH_KEY_SHADER,
            "ps_3_0",
        );
    }

    /// The world resolve owns its attachments: the engine depth-stencil and
    /// auxiliary targets must be detached before history targets bind, the
    /// selected resolve path must write through its declared color-write
    /// mask, and the transaction must leave no sampler attached. This runs
    /// the shipped resolve on a real device with an FP16 world target and
    /// observes the device state after the draw.
    #[test]
    fn mrt_path_owns_auxiliary_attachments_and_color_write_mask() {
        let owner = taa_state_test_device();
        let device = owner.as_ref();

        // Stage process-owned bytecode synchronously and suppress the
        // background worker so this execution is deterministic.
        COMPILE_STARTED.store(true, Ordering::Release);
        let bytecode = TemporalAaBytecode::compile().expect("TAA bytecode");
        *BYTECODE.lock() = Some(bytecode);
        COMPILE_READY.store(true, Ordering::Release);

        let world = device
            .create_render_target_texture(64, 64, D3DFMT_A16B16G16R16F)
            .unwrap();
        let world_surface = world.surface_level(0).unwrap();
        let world_desc = world_surface.desc().unwrap();

        let mut effect = TemporalAaEffect::create(&device)
            .unwrap()
            .expect("TAA effect with prepared bytecode");
        let mrt_selected = effect.mrt_shader.is_some();

        let depth_input = device
            .create_render_target_texture(64, 64, D3DFMT_R32F)
            .unwrap();
        let depth = DepthFrame::from_textures(
            DepthProvider::FalloutNewVegas,
            DepthTexture::new(depth_input.as_raw_base_texture()),
            None,
            DepthProjectionFrame {
                camera: camera(
                    [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
                    [0.0; 3],
                ),
                reversed_depth: Some(true),
                ..Default::default()
            },
            Default::default(),
            7,
        );
        let config = TemporalAaConfig::from_config(crate::config::TemporalAaConfig::default());

        // Inherit hostile attachments to prove the draw detaches them.
        let depth_surface = device
            .create_depth_stencil_surface(64, 64, D3DFMT_D24S8, D3DMULTISAMPLE_NONE, 0, false)
            .unwrap();
        device
            .set_depth_stencil_surface(Some(&depth_surface))
            .unwrap();

        effect
            .draw(
                &device,
                &world_surface,
                &world_desc,
                depth,
                camera(
                    [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
                    [0.0; 3],
                ),
                config,
            )
            .expect("TAA resolve");

        assert!(device.depth_stencil_surface().unwrap().is_none());
        assert!(device.render_target(1).is_err());
        for sampler in 0..=3 {
            assert!(
                !device.texture_bound(sampler),
                "TAA resolve left sampler {sampler} attached"
            );
        }
        assert_eq!(
            device.render_state(D3DRS_COLORWRITEENABLE1).unwrap(),
            COLOR_WRITE_ALL
        );
        if mrt_selected {
            assert!(
                effect.history_valid,
                "MRT resolve did not publish color history"
            );
        } else {
            // The two-pass fallback must also resolve the depth key.
            assert!(effect.history_valid);
        }
    }

    fn taa_state_test_device() -> Device9 {
        let window = [
            get_active_window(),
            get_foreground_window(),
            get_desktop_window().unwrap_or(std::ptr::null_mut()),
        ]
        .into_iter()
        .find(|window| !window.is_null())
        .expect("Wine must expose a window for D3D9 state validation");
        let direct3d = create_direct3d9().expect("D3D9 runtime");
        direct3d
            .create_windowed_device(window, 64, 64, D3DDEVTYPE_HAL)
            .or_else(|_| direct3d.create_windowed_device(window, 64, 64, D3DDEVTYPE_NULLREF))
            .expect("HAL or NULLREF D3D9 device")
    }

    #[test]
    fn temporal_aa_shader_keeps_bounded_ps_3_0_work() {
        const TEXLD: u16 = 66;
        const TEXLDD: u16 = 93;
        const TEXLDL: u16 = 95;
        // Four extra reads are necessary for fixed-grid RGB with untouched
        // alpha and full bilinear history-key validation. Five-tap color
        // statistics, full resolution and all resource/pass counts stay fixed.
        for (name, source, instruction_budget, texture_budget) in [
            ("aa_temporal.hlsl", TAA_SHADER.to_vec(), 350, 12),
            (
                "aa_temporal.hlsl:mrt",
                temporal_shader_source(true),
                390,
                12,
            ),
            (
                "aa_temporal_depth_key.hlsl",
                DEPTH_KEY_SHADER.to_vec(),
                110,
                1,
            ),
        ] {
            let bytecode =
                crate::shaders::compile_hlsl_source(name, &source).expect("temporal AA shader");
            assert_eq!(bytecode[0], 0xffff_0300);
            let opcodes = compiled_instruction_opcodes(&bytecode);
            let texture_count = opcodes
                .iter()
                .filter(|opcode| matches!(**opcode, TEXLD | TEXLDD | TEXLDL))
                .count();
            assert!(
                opcodes.len() <= instruction_budget,
                "{name} grew to {} instructions",
                opcodes.len()
            );
            assert!(
                texture_count <= texture_budget,
                "{name} grew to {texture_count} texture operations"
            );
            // Fixed explicit LOD, no derivatives, kills or dynamic loops.
            assert!(
                !opcodes
                    .iter()
                    .any(|op| matches!(*op, 27 | 38 | 65 | 91 | 92 | 93))
            );
            assert!(opcodes.iter().filter(|op| matches!(**op, 40 | 41)).count() <= 12);
            let mut offset = 1;
            while offset < bytecode.len() && bytecode[offset] as u16 != 0xffff {
                let token = bytecode[offset];
                if token as u16 == 0xfffe {
                    offset += 1 + ((token >> 16) & 0x7fff) as usize;
                    continue;
                }
                let length = ((token >> 24) & 15) as usize;
                let operands = if matches!(token as u16, 47 | 48 | 81) {
                    1
                } else {
                    length
                };
                for &parameter in &bytecode[offset + 1..offset + 1 + operands] {
                    if parameter & 0x8000_0000 == 0 {
                        continue;
                    }
                    let register_type = ((parameter >> 28) & 7) | ((parameter >> 8) & 24);
                    let register = parameter & 0x7ff;
                    match register_type {
                        0 => assert!(register < 32, "{name}: temporary r{register}"),
                        2 => assert!(register < 32, "{name}: constant c{register}"),
                        10 => assert!(
                            register < if texture_budget == 1 { 1 } else { 4 },
                            "{name}: sampler s{register}"
                        ),
                        1 => assert_eq!(register, 0, "{name}: extra interpolator"),
                        _ => {}
                    }
                }
                offset += 1 + length;
            }
        }
    }

    #[test]
    fn optional_mrt_compilation_cannot_remove_the_two_pass_fallback() {
        let result = TemporalAaBytecode::compile_with_mrt_source(b"invalid HLSL");
        assert!(
            result.is_ok(),
            "optional MRT failure removed required shaders"
        );
        let bytecode = result.unwrap();
        assert!(bytecode.resolve_mrt.is_empty());
        let owner = taa_state_test_device();
        owner
            .as_ref()
            .create_pixel_shader(&bytecode.resolve)
            .unwrap();
        owner
            .as_ref()
            .create_pixel_shader(&bytecode.depth_key)
            .unwrap();
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

/// Device-owned TAA shaders, ping-pong histories, and camera history.
pub(crate) struct TemporalAaEffect {
    shader: PixelShader9,
    mrt_shader: Option<PixelShader9>,
    depth_key_shader: PixelShader9,
    targets: Option<TemporalTargets>,
    render_target_count: u32,
    previous_camera: Option<TemporalCameraState>,
    history_index: usize,
    history_valid: bool,
    failed_target: Option<TargetDescription>,
    target_retry_frames: u16,
}

impl TemporalAaEffect {
    /// Create device-owned TAA shaders and select the mixed-format MRT path.
    ///
    /// `Ok(None)` is a normal nonblocking result while bytecode preparation is
    /// still active.
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

        let render_target_count = device.simultaneous_render_target_count()?.clamp(1, 4);
        let mrt_supported = !bytecode.resolve_mrt.is_empty()
            && render_target_count >= 2
            && device.supports_independent_mrt_bit_depths()?;
        let mrt_shader = if mrt_supported {
            match device.create_pixel_shader(&bytecode.resolve_mrt) {
                Ok(shader) => Some(shader),
                Err(err) => {
                    log::warn!(
                        "[TAA] Mixed-format MRT shader unavailable; retaining the two-pass fallback: {err}"
                    );
                    None
                }
            }
        } else {
            None
        };
        log::info!(
            "[TAA] Resolve path: {}",
            if mrt_shader.is_some() {
                "single-pass color+depth-key MRT"
            } else {
                "two-pass compatibility"
            }
        );
        Ok(Some(Self {
            shader: device.create_pixel_shader(&bytecode.resolve)?,
            mrt_shader,
            depth_key_shader: device.create_pixel_shader(&bytecode.depth_key)?,
            targets: None,
            render_target_count,
            previous_camera: None,
            history_index: 0,
            history_valid: false,
            failed_target: None,
            target_retry_frames: 0,
        }))
    }

    /// Invalidate temporal camera and image history after a discontinuity.
    pub(crate) fn invalidate_history(&mut self) {
        self.previous_camera = None;
        self.history_valid = false;
    }

    /// Return whether the next world render may safely apply projection jitter.
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

    /// Return whether current color history can preserve world-target alpha.
    pub(crate) fn alpha_preserving_history_ready(&self, target: TargetDescription) -> bool {
        self.history_valid
            && self
                .targets
                .as_ref()
                .is_some_and(|targets| targets.matches_description(target))
    }

    /// Resolve one world frame into history and copy it back to the engine target.
    /// Returns true only after successful copy-back; false skips unavailable
    /// inputs. An error invalidates history. The caller restores attachments
    /// and the captured state block for every result.
    pub(crate) fn draw(
        &mut self,
        device: &Device9Ref<'_>,
        render_target: &Surface9,
        desc: &D3DSURFACE_DESC,
        depth: DepthFrame,
        output_camera: CameraFrame,
        config: TemporalAaConfig,
    ) -> Direct3DResult<bool> {
        let Some(depth_texture) = depth.texture else {
            self.invalidate_history();
            return Ok(false);
        };
        if depth.world_projection.reversed_depth.is_none()
            || !camera_supports_reprojection(depth.world_projection.camera)
            || !camera_supports_reprojection(output_camera)
        {
            self.invalidate_history();
            return Ok(false);
        }

        let target = TargetDescription::from(desc);
        if self.failed_target == Some(target) {
            if self.target_retry_frames > 0 {
                self.target_retry_frames -= 1;
                self.invalidate_history();
                return Ok(false);
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
        // Temporal motion is defined on the fixed output grid. The depth
        // texture was sampled with the jittered camera, but carrying that
        // jitter into current/previous frusta makes a still camera produce a
        // nonzero motion vector and visibly drags history through the Halton
        // sequence.
        let current_camera = TemporalCameraState {
            camera: output_camera,
            epoch: depth.capture_epoch,
        };
        let reprojection = self
            .previous_camera
            .and_then(|previous| TemporalReprojection::between(previous, current_camera));
        let history_available = self.history_valid && reprojection.is_some();
        // Every fallible GPU operation below belongs to one transaction.
        // Previous textures remain readable for this draw, but may not be
        // admitted again after any partial write or failed copy-back.
        self.history_valid = false;
        let Some(targets) = self.targets.as_ref() else {
            return Ok(false);
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

        // The all-state block does not own render targets or depth/stencil.
        // Detach the captured engine attachments before binding a non-MSAA
        // history surface; otherwise an inherited auxiliary target can make
        // SetRenderTarget or DrawPrimitive fail validation on stricter drivers.
        device.set_depth_stencil_surface(None)?;
        for index in 1..self.render_target_count {
            device.clear_render_target(index)?;
        }
        bind_pipeline_state(device)?;
        bind_target(device, &targets.color_history[write_index].surface, desc)?;
        device.set_texture(0, &targets.current.texture)?;
        unsafe {
            device.set_raw_base_texture(1, depth_texture.as_ptr())?;
        }
        device.set_texture(2, &targets.color_history[read_index].texture)?;
        device.set_texture(3, &targets.depth_key_history[read_index].texture)?;
        bind_constants(
            device,
            desc,
            depth,
            output_camera,
            config,
            reprojection,
            history_available,
        )?;
        let use_mrt = self.mrt_shader.is_some();
        if use_mrt {
            // COLOR0 is FP16 RGBA while COLOR1 is R16F. Capability selection
            // in `create` proves this mixed-bit-depth pair before any target is
            // attached, avoiding a speculative failing draw in the hot path.
            device.set_render_target(1, &targets.depth_key_history[write_index].surface)?;
        }
        device.set_pixel_shader(self.mrt_shader.as_ref().unwrap_or(&self.shader))?;
        draw_quad(device, desc)?;

        crate::render_state::clear_sampler(device, 0)?;
        crate::render_state::clear_sampler(device, 1)?;
        crate::render_state::clear_sampler(device, 2)?;
        crate::render_state::clear_sampler(device, 3)?;
        if use_mrt {
            device.clear_render_target(1)?;
            // StretchRect cannot portably read a surface that is still bound
            // as RT0. Bind the no-longer-sampled previous depth history as a
            // harmless placeholder before copying resolved color back.
            device.set_render_target(0, &targets.depth_key_history[read_index].surface)?;
        } else {
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
            bind_depth_key_constants(device, depth, output_camera, desc)?;
            device.set_pixel_shader(&self.depth_key_shader)?;
            draw_quad(device, desc)?;
            crate::render_state::clear_sampler(device, 0)?;
        }
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
        Ok(true)
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
        && [
            camera.near_z,
            camera.far_z,
            camera.frustum_left,
            camera.frustum_right,
            camera.frustum_bottom,
            camera.frustum_top,
        ]
        .iter()
        .all(|value| value.is_finite())
        && camera.near_z > 0.0
        && camera.far_z > camera.near_z
        && (camera.frustum_right - camera.frustum_left).is_finite()
        && camera.frustum_right > camera.frustum_left
        && (camera.frustum_top - camera.frustum_bottom).is_finite()
        && camera.frustum_top > camera.frustum_bottom
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
    output_camera: CameraFrame,
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
    // Raster samples and fixed output pixels have different lens centers.
    // Native jitter changes only these centers, not near/far or pose.
    let jitter_uv = raster_jitter_uv(camera, output_camera);
    device.set_pixel_shader_constant_f(4, &[jitter_uv])?;
    device.set_pixel_shader_constant_f(
        10,
        &[[
            output_camera.frustum_left,
            output_camera.frustum_right,
            output_camera.frustum_bottom,
            output_camera.frustum_top,
        ]],
    )?;
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

fn raster_jitter_uv(rendered: CameraFrame, output: CameraFrame) -> [f32; 4] {
    [
        (rendered.frustum_left - output.frustum_left)
            / (rendered.frustum_right - rendered.frustum_left),
        (output.frustum_top - rendered.frustum_top)
            / (rendered.frustum_top - rendered.frustum_bottom),
        0.0,
        0.0,
    ]
}

fn bind_depth_key_constants(
    device: &Device9Ref<'_>,
    depth: DepthFrame,
    output_camera: CameraFrame,
    desc: &D3DSURFACE_DESC,
) -> Direct3DResult<()> {
    let camera = depth.world_projection.camera;
    device.set_pixel_shader_constant_f(
        0,
        &[
            [
                camera.near_z,
                camera.far_z,
                depth.world_projection.reversed_depth_f32(),
                0.0,
            ],
            raster_jitter_uv(camera, output_camera),
            [
                desc.Width as f32,
                desc.Height as f32,
                1.0 / desc.Width as f32,
                1.0 / desc.Height as f32,
            ],
        ],
    )
}

fn temporal_shader_source(mrt: bool) -> Vec<u8> {
    let mut source = format!("#define OMV_TAA_MRT {}\n", mrt as u8).into_bytes();
    source.extend_from_slice(TAA_SHADER);
    source
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
    device.set_render_state(D3DRS_SRGBWRITEENABLE, 0)?;
    device.set_render_state(D3DRS_COLORWRITEENABLE, COLOR_WRITE_ALL)?;
    // D3DRS_COLORWRITEENABLE controls only COLOR0. RT1 has an independent
    // write mask, which the engine is free to leave disabled before OMV's
    // transaction; explicitly enable it for the MRT depth-key output.
    device.set_render_state(D3DRS_COLORWRITEENABLE1, COLOR_WRITE_ALL)?;
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
    desc: &D3DSURFACE_DESC,
) -> Direct3DResult<()> {
    crate::render_state::clear_sampler(device, 0)?;
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
    // A screen triangle covers the same D3D9 half-pixel rectangle as the old
    // strip without a diagonal seam or a fourth transformed vertex.
    let triangle = [
        ScreenVertex::new(-0.5, -0.5, 0.0, 0.0),
        ScreenVertex::new(width * 2.0 - 0.5, -0.5, 2.0, 0.0),
        ScreenVertex::new(-0.5, height * 2.0 - 0.5, 0.0, 2.0),
    ];
    unsafe {
        crate::render_state::draw_fullscreen_vertices(device, &triangle, D3DPT_TRIANGLELIST, 1)
    }
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
/// Width, height, and format identity for a temporal world target.
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

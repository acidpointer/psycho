//! Real-device execution of the shipped TAA graph and recursive histories.
//!
//! Inputs exercise the documented raw-depth/color/lens ABI, independently of
//! the resolve equations. Affine view-ray radiance is a feature-design oracle:
//! raster samples come from the actual CameraFrame lens and a fixed output
//! lens defines the expected image. It is not a substitute for a gameplay
//! capture or a reproduction of the owner's metallic-roof scene. Upload and
//! readback are test-only; production never synchronizes for these images.

use super::*;
use crate::backend::{
    CameraTransformFrame, DepthImageFrame, DepthProjectionFrame, DepthProvider, DepthTexture,
};
use libpsycho::os::windows::{
    directx9::{
        D3DDEVTYPE_HAL, D3DDEVTYPE_NULLREF, Device9, DynamicRgba32fTexture9, create_direct3d9,
    },
    winapi::{get_active_window, get_desktop_window, get_foreground_window},
};

const WIDTH: u32 = 64;
const HEIGHT: u32 = 32;
// This only transfers supplied texels into the FP16 world target. Neither
// the temporal algorithm nor its oracle is implemented by this shader.
const TRANSFER: &[u8] = b"sampler2D Input : register(s0); float4 Main(float2 uv : TEXCOORD0) : COLOR0 { return tex2Dlod(Input, float4(uv,0,0)); }";

fn camera() -> CameraFrame {
    CameraFrame {
        near_z: 5.0,
        far_z: 1000.0,
        aspect_ratio: WIDTH as f32 / HEIGHT as f32,
        frustum_left: -1.0,
        frustum_right: 1.0,
        frustum_bottom: -0.5,
        frustum_top: 0.5,
        world_transform: CameraTransformFrame {
            rotation: [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
            translation: [0.0; 3],
            scale: 1.0,
            available: true,
        },
        available: true,
    }
}

fn device() -> Device9 {
    let window = [
        get_active_window(),
        get_foreground_window(),
        get_desktop_window().unwrap_or(std::ptr::null_mut()),
    ]
    .into_iter()
    .find(|window| !window.is_null())
    .expect("D3D9 test window");
    create_direct3d9()
        .expect("D3D9")
        .create_windowed_device(window, WIDTH, HEIGHT, D3DDEVTYPE_HAL)
        .or_else(|_| {
            create_direct3d9().expect("D3D9").create_windowed_device(
                window,
                WIDTH,
                HEIGHT,
                D3DDEVTYPE_NULLREF,
            )
        })
        .expect("real D3D9 device")
}

struct Harness {
    owner: Device9,
    effect: TemporalAaEffect,
    world: Texture9,
    upload: DynamicRgba32fTexture9,
    depth: DynamicRgba32fTexture9,
    transfer: PixelShader9,
    epoch: u64,
}

impl Harness {
    fn new(mrt: bool) -> Self {
        let owner = device();
        let d = owner.as_ref();
        let bytecode = TemporalAaBytecode::compile().expect("production TAA bytecode");
        let mrt_shader = mrt.then(|| {
            assert!(d.simultaneous_render_target_count().unwrap() >= 2);
            assert!(d.supports_independent_mrt_bit_depths().unwrap());
            d.create_pixel_shader(&bytecode.resolve_mrt)
                .expect("MRT shader")
        });
        // Construct only device ownership, avoiding process compiler globals
        // shared with other concurrently running tests.
        let effect = TemporalAaEffect {
            shader: d.create_pixel_shader(&bytecode.resolve).unwrap(),
            mrt_shader,
            depth_key_shader: d.create_pixel_shader(&bytecode.depth_key).unwrap(),
            targets: None,
            render_target_count: d.simultaneous_render_target_count().unwrap().clamp(1, 4),
            previous_camera: None,
            history_index: 0,
            history_valid: false,
            failed_target: None,
            target_retry_frames: 0,
        };
        let world = d
            .create_render_target_texture(WIDTH, HEIGHT, D3DFMT_A16B16G16R16F)
            .unwrap();
        let upload = d.create_dynamic_rgba32f_texture(WIDTH, HEIGHT).unwrap();
        let depth = d.create_dynamic_rgba32f_texture(WIDTH, HEIGHT).unwrap();
        let transfer = d
            .create_pixel_shader(
                &shaders::compile_hlsl_source("taa-test-transfer", TRANSFER).unwrap(),
            )
            .unwrap();
        Self {
            owner,
            effect,
            world,
            upload,
            depth,
            transfer,
            epoch: 0,
        }
    }

    fn transfer(&self, input: &Texture9, output: &Surface9) {
        let d = self.owner.as_ref();
        d.set_depth_stencil_surface(None).unwrap();
        for slot in 1..self.effect.render_target_count {
            d.clear_render_target(slot).unwrap();
        }
        bind_pipeline_state(&d).unwrap();
        let desc = output.desc().unwrap();
        bind_target(&d, output, &desc).unwrap();
        d.set_texture(0, input).unwrap();
        d.set_sampler_state(0, D3DSAMP_MINFILTER, D3DTEXF_POINT.0 as u32)
            .unwrap();
        d.set_sampler_state(0, D3DSAMP_MAGFILTER, D3DTEXF_POINT.0 as u32)
            .unwrap();
        d.set_pixel_shader(&self.transfer).unwrap();
        d.begin_scene().unwrap();
        draw_quad(&d, &desc).unwrap();
        d.end_scene().unwrap();
        crate::render_state::clear_sampler(&d, 0).unwrap();
    }

    fn frame(
        &mut self,
        pixels: &[[f32; 4]],
        raw_depth: &[f32],
        rendered: CameraFrame,
        output: CameraFrame,
        reversed: bool,
        settings: config::TemporalAaConfig,
    ) -> Vec<[f32; 4]> {
        self.epoch += 1;
        self.upload.write_discard(pixels).unwrap();
        self.depth
            .write_discard(
                &raw_depth
                    .iter()
                    .map(|depth| [*depth, 0.0, 0.0, 1.0])
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        let surface = self.world.surface_level(0).unwrap();
        self.transfer(self.upload.texture(), &surface);
        let desc = surface.desc().unwrap();
        let d = self.owner.as_ref();
        let depth = DepthFrame::from_textures(
            DepthProvider::FalloutNewVegas,
            DepthTexture::new(self.depth.texture().as_raw_base_texture()),
            None,
            DepthProjectionFrame {
                camera: rendered,
                reversed_depth: Some(reversed),
                sampled_depth_bits: 24,
                image: DepthImageFrame {
                    color_surface: surface.as_raw() as usize,
                    color_extent: [WIDTH, HEIGHT],
                    allocation_extent: [WIDTH, HEIGHT],
                    sampled_extent: [WIDTH, HEIGHT],
                },
                ..Default::default()
            },
            Default::default(),
            self.epoch,
        );
        d.begin_scene().unwrap();
        self.effect
            .draw(
                &d,
                &surface,
                &desc,
                depth,
                output,
                TemporalAaConfig::from_config(settings),
            )
            .unwrap();
        d.end_scene().unwrap();
        self.read(&surface)
    }

    fn read(&self, surface: &Surface9) -> Vec<[f32; 4]> {
        let d = self.owner.as_ref();
        let staging = d
            .create_system_memory_surface(WIDTH, HEIGHT, D3DFMT_A16B16G16R16F)
            .unwrap();
        d.copy_render_target_data(surface, &staging).unwrap();
        staging.read_rgba16f().unwrap()
    }

    fn keys(&self) -> Vec<[f32; 4]> {
        let d = self.owner.as_ref();
        let output = d
            .create_render_target_texture(WIDTH, HEIGHT, D3DFMT_A16B16G16R16F)
            .unwrap();
        let surface = output.surface_level(0).unwrap();
        self.transfer(
            &self.effect.targets.as_ref().unwrap().depth_key_history[self.effect.history_index]
                .texture,
            &surface,
        );
        self.read(&surface)
    }
}

fn affine_samples(lens: CameraFrame) -> Vec<[f32; 4]> {
    (0..WIDTH * HEIGHT)
        .map(|index| {
            let u = (index % WIDTH) as f32 / WIDTH as f32 + 0.5 / WIDTH as f32;
            let v = (index / WIDTH) as f32 / HEIGHT as f32 + 0.5 / HEIGHT as f32;
            // Color is a fixed affine function of the native view ray. Changing
            // the actual production lens changes sampling, not this radiance.
            let x = lens.frustum_left + u * (lens.frustum_right - lens.frustum_left);
            let y = lens.frustum_top + v * (lens.frustum_bottom - lens.frustum_top);
            [
                0.5 + x * 0.25,
                0.5 + y * 0.25,
                0.25,
                if index % 2 == 0 { 0.25 } else { 0.75 },
            ]
        })
        .collect()
}

#[test]
fn fixed_grid_affine_radiance_is_invariant_over_jitter_and_history_weights() {
    let output = camera();
    let expected = affine_samples(output);
    for mrt in [false, true] {
        for reversed in [false, true] {
            for weight in [0.0, 0.9] {
                let mut h = Harness::new(mrt);
                let settings = config::TemporalAaConfig {
                    history_weight: weight,
                    sharpness: 0.0,
                    ..Default::default()
                };
                let depths = vec![0.5; (WIDTH * HEIGHT) as usize];
                h.frame(&expected, &depths, output, output, reversed, settings);
                for jitter in [[0.45, -0.35], [-0.4, 0.3], [0.2, 0.4], [-0.35, -0.4]] {
                    let rendered = output.with_pixel_jitter(jitter, WIDTH, HEIGHT).unwrap();
                    let input = affine_samples(rendered);
                    let image = h.frame(&input, &depths, rendered, output, reversed, settings);
                    for y in 2..HEIGHT - 2 {
                        for x in 2..WIDTH - 2 {
                            let index = (y * WIDTH + x) as usize;
                            for channel in 0..3 {
                                assert!(
                                    (image[index][channel] - expected[index][channel]).abs()
                                        <= 0.001,
                                    "fixed-grid mismatch: mrt={mrt} reversed={reversed} weight={weight} jitter={jitter:?} pixel={x},{y} channel={channel}: {} expected {}",
                                    image[index][channel],
                                    expected[index][channel]
                                );
                            }
                            assert_eq!(image[index][3], input[index][3], "engine alpha changed");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn mrt_and_two_pass_images_match_for_geometry_sky_invalid_and_alpha() {
    let mut ordinary = Harness::new(false);
    let mut mrt = Harness::new(true);
    let output = camera();
    for reversed in [false, true] {
        ordinary.effect.invalidate_history();
        mrt.effect.invalidate_history();
        for jitter in [[0.0, 0.0], [0.4, -0.3], [-0.35, 0.4]] {
            let rendered = output.with_pixel_jitter(jitter, WIDTH, HEIGHT).unwrap();
            let pixels = affine_samples(rendered);
            let depths: Vec<_> = (0..WIDTH * HEIGHT)
                .map(|index| match (index % WIDTH) / 16 {
                    0 => {
                        if reversed {
                            0.0
                        } else {
                            1.0
                        }
                    }
                    1 => 0.5,
                    2 => -1.0,
                    _ => f32::NAN,
                })
                .collect();
            let a = ordinary.frame(
                &pixels,
                &depths,
                rendered,
                output,
                reversed,
                Default::default(),
            );
            let b = mrt.frame(
                &pixels,
                &depths,
                rendered,
                output,
                reversed,
                Default::default(),
            );
            assert_eq!(a, b, "MRT color differs from fallback");
            assert_eq!(ordinary.keys(), mrt.keys(), "MRT keys differ from fallback");
            for (pixel, input) in a.iter().zip(&pixels) {
                assert!(pixel.iter().all(|value| value.is_finite()));
                assert_eq!(pixel[3], input[3]);
            }
        }
    }
}

#[test]
fn sharpening_never_creates_a_peak_outside_current_radiance_bounds() {
    for mrt in [false, true] {
        let mut h = Harness::new(mrt);
        let output = camera();
        let mut pixels = vec![[0.0, 0.0, 0.0, 0.5]; (WIDTH * HEIGHT) as usize];
        let index = (HEIGHT / 2 * WIDTH + WIDTH / 2) as usize;
        pixels[index] = [1.0, 0.5, 0.25, 0.5];
        let depth = vec![0.5; pixels.len()];
        let settings = config::TemporalAaConfig {
            history_weight: 0.0,
            sharpness: 1.0,
            clamp_strength: 2.0,
            ..Default::default()
        };
        h.frame(&pixels, &depth, output, output, false, settings);
        let image = h.frame(&pixels, &depth, output, output, false, settings);
        for channel in 0..3 {
            assert!(
                image[index][channel] <= pixels[index][channel],
                "sharpening invented radiance: {} > {}",
                image[index][channel],
                pixels[index][channel]
            );
        }
        assert_eq!(image[index][3], 0.5);
    }
}

#[test]
fn failed_copy_invalidates_the_recursive_history() {
    let mut h = Harness::new(false);
    let output = camera();
    let pixels = affine_samples(output);
    h.frame(
        &pixels,
        &vec![0.5; pixels.len()],
        output,
        output,
        false,
        Default::default(),
    );
    let other = Harness::new(false);
    let foreign = other.world.surface_level(0).unwrap();
    let desc = foreign.desc().unwrap();
    let depth = DepthFrame::from_textures(
        DepthProvider::FalloutNewVegas,
        DepthTexture::new(h.depth.texture().as_raw_base_texture()),
        None,
        DepthProjectionFrame {
            camera: output,
            reversed_depth: Some(false),
            ..Default::default()
        },
        Default::default(),
        h.epoch + 1,
    );
    // A real cross-device surface is invalid for this device's StretchRect.
    // No mocked HRESULT or production failure injection is used.
    assert!(
        h.effect
            .draw(
                &h.owner.as_ref(),
                &foreign,
                &desc,
                depth,
                output,
                TemporalAaConfig::from_config(Default::default())
            )
            .is_err()
    );
    assert!(
        !h.effect.history_valid,
        "failed GPU transaction left history admissible"
    );
}

#[test]
fn camera_motion_tracks_world_radiance_and_sky_ignores_translation() {
    for mrt in [false, true] {
        for reversed in [false, true] {
            for sky in [false, true] {
                let mut h = Harness::new(mrt);
                let previous = camera();
                let settings = config::TemporalAaConfig {
                    history_weight: 0.98,
                    sharpness: 0.0,
                    clamp_strength: 2.0,
                    ..Default::default()
                };
                // Plane at z=10: standard D3D perspective depth is 100/199.
                let raw = if sky {
                    if reversed { 0.0 } else { 1.0 }
                } else if reversed {
                    99.0 / 199.0
                } else {
                    100.0 / 199.0
                };
                let depth = vec![raw; (WIDTH * HEIGHT) as usize];
                h.frame(
                    &affine_samples(previous),
                    &depth,
                    previous,
                    previous,
                    reversed,
                    settings,
                );
                let mut current = previous;
                // Native camera basis columns are forward/up/right; identity's
                // world Z is the screen-horizontal direction, not world X.
                current.world_transform.translation = [0.0, 0.0, 0.625];
                let mut expected = affine_samples(current);
                if !sky {
                    for pixel in &mut expected {
                        pixel[0] += 0.625 / 10.0 * 0.25;
                    }
                }
                let image = h.frame(&expected, &depth, current, current, reversed, settings);
                for y in 2..HEIGHT - 2 {
                    for x in 3..WIDTH - 3 {
                        let index = (y * WIDTH + x) as usize;
                        assert!(
                            (image[index][0] - expected[index][0]).abs() < 0.001,
                            "camera displacement incorrect: sky={sky} reversed={reversed} actual={} expected={}",
                            image[index][0],
                            expected[index][0]
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn history_filter_cannot_mix_sky_into_foreground_radiance() {
    for mrt in [false, true] {
        for reversed in [false, true] {
            let mut h = Harness::new(mrt);
            let previous = camera();
            let geometry = if reversed {
                99.0 / 199.0
            } else {
                100.0 / 199.0
            };
            let sky = if reversed { 0.0 } else { 1.0 };
            let settings = config::TemporalAaConfig {
                history_weight: 0.98,
                sharpness: 0.0,
                ..Default::default()
            };
            let old_color: Vec<_> = (0..WIDTH * HEIGHT)
                .map(|i| {
                    if i % WIDTH < WIDTH / 2 {
                        [0.5, 0.5, 0.5, 0.5]
                    } else {
                        [1.0, 1.0, 1.0, 0.5]
                    }
                })
                .collect();
            let old_depth: Vec<_> = (0..WIDTH * HEIGHT)
                .map(|i| if i % WIDTH < WIDTH / 2 { geometry } else { sky })
                .collect();
            h.frame(
                &old_color, &old_depth, previous, previous, reversed, settings,
            );
            let mut current = previous;
            current.world_transform.translation[2] = 0.078125;
            let pixels: Vec<_> = (0..WIDTH * HEIGHT)
                .map(|i| {
                    if i % WIDTH == WIDTH / 2 - 2 {
                        [1.0, 1.0, 1.0, 0.5]
                    } else {
                        [0.5, 0.5, 0.5, 0.5]
                    }
                })
                .collect();
            let image = h.frame(
                &pixels,
                &vec![geometry; pixels.len()],
                current,
                current,
                reversed,
                settings,
            );
            for y in 2..HEIGHT - 2 {
                let i = (y * WIDTH + WIDTH / 2 - 1) as usize;
                assert!(
                    (image[i][0] - 0.5).abs() < 0.001,
                    "bilinear sky leaked into geometry: {}",
                    image[i][0]
                );
            }
        }
    }
}

#[test]
fn rotated_camera_keeps_world_affine_radiance_aligned() {
    for mrt in [false, true] {
        for reversed in [false, true] {
            let mut h = Harness::new(mrt);
            let previous = camera();
            let depth = vec![
                if reversed {
                    99.0 / 199.0
                } else {
                    100.0 / 199.0
                };
                (WIDTH * HEIGHT) as usize
            ];
            let settings = config::TemporalAaConfig {
                history_weight: 0.98,
                sharpness: 0.0,
                ..Default::default()
            };
            h.frame(
                &affine_samples(previous),
                &depth,
                previous,
                previous,
                reversed,
                settings,
            );
            let mut current = previous;
            let (s, c) = 0.1_f32.sin_cos();
            current.world_transform.rotation = [[1.0, 0.0, 0.0], [0.0, c, -s], [0.0, s, c]];
            // Radiance is affine in world right/up, evaluated at each current ray.
            let expected: Vec<_> = affine_samples(current)
                .into_iter()
                .map(|mut p| {
                    let x = (p[0] - 0.5) * 4.0;
                    let y = (p[1] - 0.5) * 4.0;
                    p[0] = 0.5 + 0.25 * (c * x + s * y);
                    p[1] = 0.5 + 0.25 * (c * y - s * x);
                    p
                })
                .collect();
            let image = h.frame(&expected, &depth, current, current, reversed, settings);
            for y in 5..HEIGHT - 5 {
                for x in 5..WIDTH - 5 {
                    let i = (y * WIDTH + x) as usize;
                    for channel in 0..3 {
                        assert!(
                            (image[i][channel] - expected[i][channel]).abs() < 0.001,
                            "rotated world radiance moved: {} expected {}",
                            image[i][channel],
                            expected[i][channel]
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn appearing_and_disappearing_sky_radiance_does_not_leave_history_trails() {
    for mrt in [false, true] {
        for reversed in [false, true] {
            let mut h = Harness::new(mrt);
            let camera = camera();
            let depth = vec![if reversed { 0.0 } else { 1.0 }; (WIDTH * HEIGHT) as usize];
            for radiance in [0.0, 1.0, 0.0, 0.02, 0.02] {
                let pixels = vec![[radiance, radiance, radiance, 0.5]; depth.len()];
                let image = h.frame(
                    &pixels,
                    &depth,
                    camera,
                    camera,
                    reversed,
                    Default::default(),
                );
                for pixel in image {
                    assert!(
                        (pixel[0] - radiance).abs() < 0.0001,
                        "stale sky radiance persisted"
                    );
                }
            }
        }
    }
}

#[test]
fn unavailable_or_degenerate_projection_skips_without_overwriting_world_color() {
    let mut h = Harness::new(false);
    let camera = camera();
    let pixels = affine_samples(camera);
    let original = h.frame(
        &pixels,
        &vec![0.5; pixels.len()],
        camera,
        camera,
        false,
        Default::default(),
    );
    let surface = h.world.surface_level(0).unwrap();
    let desc = surface.desc().unwrap();
    let mut invalid = camera;
    invalid.frustum_right = invalid.frustum_left;
    let depth = DepthFrame::from_textures(
        DepthProvider::FalloutNewVegas,
        DepthTexture::new(h.depth.texture().as_raw_base_texture()),
        None,
        DepthProjectionFrame {
            camera,
            reversed_depth: Some(false),
            ..Default::default()
        },
        Default::default(),
        h.epoch + 1,
    );
    let d = h.owner.as_ref();
    d.begin_scene().unwrap();
    let resolved = h
        .effect
        .draw(
            &d,
            &surface,
            &desc,
            depth,
            invalid,
            TemporalAaConfig::from_config(Default::default()),
        )
        .unwrap();
    d.end_scene().unwrap();
    assert!(!resolved, "degenerate output lens was admitted");
    assert!(!h.effect.history_valid);
    assert_eq!(h.read(&surface), original);
    assert!(
        !h.effect
            .draw(
                &d,
                &surface,
                &desc,
                DepthFrame::default(),
                camera,
                TemporalAaConfig::from_config(Default::default())
            )
            .unwrap()
    );
}

#[test]
fn invalid_numeric_settings_do_not_poison_recursive_color_history() {
    for mrt in [false, true] {
        let mut h = Harness::new(mrt);
        let output = camera();
        let pixels = affine_samples(output);
        let depth = vec![0.5; pixels.len()];
        h.frame(&pixels, &depth, output, output, false, Default::default());
        let invalid = config::TemporalAaConfig {
            history_weight: f32::NAN,
            clamp_strength: f32::INFINITY,
            sharpness: f32::NAN,
            jitter_scale: f32::NAN,
            ..Default::default()
        };
        let image = h.frame(&pixels, &depth, output, output, false, invalid);
        assert!(
            image.iter().flatten().all(|value| value.is_finite()),
            "invalid config reached history"
        );
        for (actual, expected) in image
            .iter()
            .zip(&pixels)
            .skip(2 * WIDTH as usize)
            .take((HEIGHT - 4) as usize * WIDTH as usize)
        {
            assert!(
                (actual[0] - expected[0]).abs() < 0.001,
                "invalid settings corrupted finite radiance: {} expected {}",
                actual[0],
                expected[0]
            );
        }
        assert!(
            TemporalAaConfig::from_config(invalid)
                .jitter_scale()
                .is_finite(),
            "invalid setting poisons native projection admission"
        );
        let image = h.frame(&pixels, &depth, output, output, false, Default::default());
        assert!(
            image.iter().flatten().all(|value| value.is_finite()),
            "bad config persisted into history"
        );
    }
}

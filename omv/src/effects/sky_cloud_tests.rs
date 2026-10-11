//! Controlled sky design regressions through the production D3D9 native pairs.
//!
//! The native vertex/pixel templates and frame-constant preparation execute
//! unchanged. Test-owned geometry and authored RGBA inputs specify the intended
//! brightness/detail behavior; they are not reconstructed gameplay captures.
//! Each test owns its device and readback resources; there is no runtime state.

use super::*;
use libpsycho::os::windows::{directx9::*, winapi::get_desktop_window};

const SIZE: u32 = 32;

#[repr(C)]
#[derive(Clone, Copy)]
struct CloudVertex {
    position: [f32; 4],
    uv: [f32; 4],
    color: [f32; 4],
}

struct Harness {
    owner: Device9,
    vertex: VertexShader9,
    pixel: PixelShader9,
    declaration: VertexDeclaration9,
    first: Texture9,
    second: Texture9,
    output: Texture9,
    staging: Surface9,
    normals: bool,
    pixel_kind: usize,
    elevation: f32,
    visibility: f32,
}

fn frame() -> crate::backend::NativeSkyFrame {
    crate::backend::NativeSkyFrame {
        sky_upper: [0.3, 0.45, 0.7],
        sky_lower: [0.4, 0.5, 0.65],
        horizon: [0.6, 0.55, 0.5],
        sun_light: [0.8, 0.7, 0.5],
        sun_disk: [0.8, 0.7, 0.5],
        sun_direction: [0.0, 0.0, 1.0],
        daylight: 1.0,
        game_hour: 12.0,
        is_exterior: true,
        reversed_depth: true,
    }
}

impl Harness {
    fn new(normals: bool, quantized: bool) -> Self {
        Self::pair(
            VS_CLOUDS,
            if normals { PS_CLOUD_NORMALS } else { PS_CLOUDS },
            quantized,
        )
    }

    fn pair(vertex_index: usize, pixel_kind: usize, quantized: bool) -> Self {
        let owner = create_direct3d9()
            .unwrap()
            .create_windowed_device(get_desktop_window().unwrap(), SIZE, SIZE, D3DDEVTYPE_HAL)
            .unwrap();
        let device = owner.as_ref();
        let code = |index: usize| {
            let template = &TEMPLATES[index];
            crate::shaders::compile_hlsl_source_target(
                template.label,
                &template_source(template),
                template_profile(template),
            )
            .unwrap()
        };
        let vertex = device.create_vertex_shader(&code(vertex_index)).unwrap();
        let pixel = device.create_pixel_shader(&code(pixel_kind)).unwrap();
        let element = |offset, kind, usage| D3DVERTEXELEMENT9 {
            Stream: 0,
            Offset: offset,
            Type: kind,
            Method: 0,
            Usage: usage,
            UsageIndex: 0,
        };
        let declaration = device
            .create_vertex_declaration(&[
                element(0, D3DDECLTYPE_FLOAT4.0 as u8, D3DDECLUSAGE_POSITION.0 as u8),
                element(
                    16,
                    D3DDECLTYPE_FLOAT4.0 as u8,
                    D3DDECLUSAGE_TEXCOORD.0 as u8,
                ),
                element(32, D3DDECLTYPE_FLOAT4.0 as u8, D3DDECLUSAGE_COLOR.0 as u8),
                D3DVERTEXELEMENT9 {
                    Stream: 0xFF,
                    Type: D3DDECLTYPE_UNUSED.0 as u8,
                    ..Default::default()
                },
            ])
            .unwrap();
        let input = || {
            device
                .create_texture(SIZE, SIZE, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)
                .unwrap()
        };
        let first = input();
        let second = input();
        let format = if quantized {
            D3DFMT_A8R8G8B8
        } else {
            D3DFMT_A16B16G16R16F
        };
        let output = device
            .create_render_target_texture(SIZE, SIZE, format)
            .unwrap();
        let staging = device
            .create_system_memory_surface(SIZE, SIZE, format)
            .unwrap();
        Self {
            owner,
            vertex,
            pixel,
            declaration,
            first,
            second,
            output,
            staging,
            normals: pixel_kind == PS_CLOUD_NORMALS,
            pixel_kind,
            elevation: 0.0,
            visibility: 1.0,
        }
    }

    fn image(&self, first: &[u32], second: &[u32]) {
        self.first.write_level0_argb(SIZE, SIZE, first).unwrap();
        self.second.write_level0_argb(SIZE, SIZE, second).unwrap();
    }

    fn draw(
        &self,
        frame: crate::backend::NativeSkyFrame,
        brightness: f32,
        blend: f32,
    ) -> Vec<[f32; 4]> {
        self.draw_with_transparency(frame, brightness, blend, 1.0)
    }

    fn draw_with_transparency(
        &self,
        frame: crate::backend::NativeSkyFrame,
        brightness: f32,
        blend: f32,
        transparency: f32,
    ) -> Vec<[f32; 4]> {
        let settings = NativeSkySettings::from(crate::config::NativeSkyConfig {
            cloud_brightness: brightness,
            cloud_transparency: transparency,
            cloud_normals: self.normals,
            sunset_red: 0.0,
            sunset_green: 0.0,
            sunset_blue: 0.0,
            ..Default::default()
        });
        self.draw_settings(frame, settings, blend)
    }

    fn draw_settings(
        &self,
        frame: crate::backend::NativeSkyFrame,
        settings: NativeSkySettings,
        blend: f32,
    ) -> Vec<[f32; 4]> {
        self.draw_environment(
            frame,
            settings,
            blend,
            crate::backend::EnvironmentFrame::default(),
        )
    }

    fn draw_environment(
        &self,
        frame: crate::backend::NativeSkyFrame,
        settings: NativeSkySettings,
        blend: f32,
        environment: crate::backend::EnvironmentFrame,
    ) -> Vec<[f32; 4]> {
        let device = self.owner.as_ref();
        device.set_depth_stencil_surface(None).unwrap();
        for slot in 1..device.simultaneous_render_target_count().unwrap().min(4) {
            device.clear_render_target(slot).unwrap();
        }
        for (state, value) in [
            (D3DRS_ZENABLE, 0),
            (D3DRS_ZWRITEENABLE, 0),
            (D3DRS_STENCILENABLE, 0),
            (D3DRS_ALPHATESTENABLE, 0),
            (D3DRS_ALPHABLENDENABLE, 0),
            (D3DRS_CULLMODE, D3DCULL_NONE.0 as u32),
            (D3DRS_FOGENABLE, 0),
            (D3DRS_SCISSORTESTENABLE, 0),
            (D3DRS_COLORWRITEENABLE, 15),
            (D3DRS_SRGBWRITEENABLE, 0),
            (D3DRS_MULTISAMPLEANTIALIAS, 0),
            (D3DRS_MULTISAMPLEMASK, u32::MAX),
        ] {
            device.set_render_state(state, value).unwrap();
        }
        for stage in 0..=1 {
            for (state, value) in [
                (D3DSAMP_ADDRESSU, D3DTADDRESS_CLAMP.0 as u32),
                (D3DSAMP_ADDRESSV, D3DTADDRESS_CLAMP.0 as u32),
                (D3DSAMP_MINFILTER, D3DTEXF_POINT.0 as u32),
                (D3DSAMP_MAGFILTER, D3DTEXF_POINT.0 as u32),
                (D3DSAMP_MIPFILTER, D3DTEXF_NONE.0 as u32),
                (D3DSAMP_SRGBTEXTURE, 0),
            ] {
                device.set_sampler_state(stage, state, value).unwrap();
            }
        }
        device
            .set_render_target(0, &self.output.surface_level(0).unwrap())
            .unwrap();
        device
            .set_viewport(&D3DVIEWPORT9 {
                X: 0,
                Y: 0,
                Width: SIZE,
                Height: SIZE,
                MinZ: 0.0,
                MaxZ: 1.0,
            })
            .unwrap();
        device.set_texture(0, &self.first).unwrap();
        device.set_texture(1, &self.second).unwrap();
        device.set_vertex_shader(&self.vertex).unwrap();
        device.set_pixel_shader(&self.pixel).unwrap();
        device.set_vertex_declaration(&self.declaration).unwrap();
        device
            .set_vertex_shader_constant_f(
                0,
                &[
                    [1.0, 0.0, 0.0, 0.0],
                    [
                        0.0,
                        1.0,
                        0.0,
                        if self.pixel_kind == PS_ATMOSPHERE {
                            -4.0
                        } else {
                            0.0
                        },
                    ],
                    [0.0, 0.0, 1.0, 0.0],
                    [0.0, 0.0, 0.0, 1.0],
                    [1.0, 1.0, 1.0, self.visibility],
                    [0.0; 4],
                    [0.0; 4],
                ],
            )
            .unwrap();
        device
            .set_vertex_shader_constant_f(12, &[[0.0; 4]])
            .unwrap();
        device
            .set_pixel_shader_constant_f(4, &[[blend, 1.0, 0.0, 0.0]])
            .unwrap();
        upload_constants(
            &device,
            prepare_sky_frame(frame, settings, environment).constants,
            3,
        )
        .unwrap();
        let vertex = |x, y, u, v| CloudVertex {
            // The atmosphere's real vertex shader publishes mesh position as
            // the eye ray. This translated plane has nonzero horizontal rays
            // at every pixel while its MVP still covers the whole target.
            position: if self.pixel_kind == PS_ATMOSPHERE {
                [x, y + 4.0, self.elevation, 1.0]
            } else {
                [x, y, 1.0, 1.0]
            },
            uv: [u, v, 0.0, 0.0],
            color: [1.0, 0.0, 0.0, 1.0],
        };
        let quad = [
            vertex(-1.0, 1.0, 0.0, 0.0),
            vertex(1.0, 1.0, 1.0, 0.0),
            vertex(-1.0, -1.0, 0.0, 1.0),
            vertex(1.0, -1.0, 1.0, 1.0),
        ];
        device.begin_scene().unwrap();
        // SAFETY: Four initialized declaration-matching vertices remain alive
        // through the synchronous two-primitive triangle-strip submission.
        unsafe {
            device
                .draw_primitive_up(D3DPT_TRIANGLESTRIP, 2, &quad)
                .unwrap();
        }
        device.end_scene().unwrap();
        device
            .copy_render_target_data(&self.output.surface_level(0).unwrap(), &self.staging)
            .unwrap();
        if self.staging.desc().unwrap().Format == D3DFMT_A8R8G8B8 {
            self.staging.read_rgba8().unwrap()
        } else {
            self.staging.read_rgba16f().unwrap()
        }
    }
}

#[test]
fn geometric_horizon_reaches_weather_target_in_both_depth_modes() {
    // The approved design boundary is the native horizon RGB, which is also
    // the terrain endpoint once the frame owner selects the active fog color.
    // These are explicit color-control fixtures, not captured scene constants.
    for reversed in [false, true] {
        let h = Harness::pair(
            VS_ATMOSPHERE + if reversed { 0 } else { VS_FORWARD_OFFSET },
            PS_ATMOSPHERE,
            false,
        );
        let mut scene = frame();
        scene.reversed_depth = reversed;
        let settings = NativeSkySettings::from(crate::config::NativeSkyConfig {
            sun_strength: 0.0,
            ..Default::default()
        });
        for pixel in h.draw_settings(scene, settings, 0.0) {
            for (actual, target) in pixel[..3].iter().zip(scene.horizon) {
                assert!(
                    (*actual - target).abs() <= 1.2 / 255.0,
                    "horizon does not reach weather target: {pixel:?}, target={:?}",
                    scene.horizon
                );
            }
            assert_eq!(pixel[3], 1.0);
        }
    }
}

#[test]
fn selected_solar_color_controls_disk_without_changing_authored_coverage() {
    let h = Harness::pair(VS_CELESTIAL, PS_CELESTIAL_SUN, false);
    let image: Vec<_> = (0..SIZE * SIZE)
        .map(|i| match i % SIZE / 8 {
            0 => 0x40000000,
            1 => 0x80606060,
            2 => 0xC0A0A0A0,
            _ => 0xFFFFFFFF,
        })
        .collect();
    h.image(&image, &image);
    let mut scene = frame();
    scene.sun_light = [0.3, 0.8, 0.5];
    scene.sun_disk = [0.9, 0.6, 0.3];
    let draw = |disk| {
        h.draw_settings(
            scene,
            NativeSkySettings::from(crate::config::NativeSkyConfig {
                use_sun_disk_color: disk,
                sunset_red: 0.0,
                sunset_green: 0.0,
                sunset_blue: 0.0,
                ..Default::default()
            }),
            0.0,
        )
    };
    let light = draw(false);
    let disk = draw(true);
    assert!(
        light.iter().zip(&disk).any(|(a, b)| a[..3] != b[..3]),
        "the selected solar source did not affect the sun disk"
    );
    for (index, (a, b)) in light.iter().zip(&disk).enumerate() {
        assert_eq!(a[3], b[3], "solar tint changed native coverage");
        if index % (SIZE as usize) < 8 {
            assert_eq!(b[..3], [0.0; 3], "black authored texel became an emitter");
        }
        assert!(b.iter().all(|v| v.is_finite()));
    }
}

#[test]
fn exterior_fog_owns_the_horizon_with_native_and_zero_thickness_fallbacks() {
    let mut h = Harness::pair(VS_ATMOSPHERE, PS_ATMOSPHERE, false);
    let mut scene = frame();
    scene.sun_direction = [0.0, 1.0, 0.0];
    let environment = crate::backend::EnvironmentFrame {
        fog_available: true,
        fog_color: [0.7, 0.65, 0.55],
        ..Default::default()
    };
    for exterior in [false, true] {
        scene.is_exterior = exterior;
        for thickness in [f32::from_bits(1), 0.7068965, 8.0] {
            let settings = NativeSkySettings::from(crate::config::NativeSkyConfig {
                atmosphere_thickness: thickness,
                sun_strength: 8.0,
                ..Default::default()
            });
            let target = if exterior {
                environment.fog_color
            } else {
                scene.horizon
            };
            for pixel in h.draw_environment(scene, settings, 0.0, environment) {
                assert!(pixel.iter().all(|v| v.is_finite()));
                for (actual, expected) in pixel[..3].iter().zip(target) {
                    assert!(
                        (*actual - expected).abs() < 1.2 / 255.0,
                        "fog boundary was repainted: {pixel:?}, target={target:?}"
                    );
                }
            }
        }
    }
    scene.sky_upper = [0.2; 3];
    scene.sky_lower = [0.2; 3];
    let settings = NativeSkySettings::from(crate::config::NativeSkyConfig {
        atmosphere_thickness: 0.0,
        ..Default::default()
    });
    for pixel in h.draw_environment(scene, settings, 0.0, environment) {
        assert!(pixel[..3].iter().all(|v| (*v - 0.2).abs() < 1.2 / 255.0));
    }
    scene = frame();
    let settings = NativeSkySettings::from(crate::config::NativeSkyConfig {
        sun_strength: 0.0,
        ..Default::default()
    });
    let mut previous_red = 1.0;
    for elevation in [0.0, 0.05, 0.1, 0.2, 0.5, 1.0, 4.0, 64.0] {
        h.elevation = elevation;
        let image = h.draw_settings(scene, settings, 0.0);
        let red = image[(SIZE * SIZE / 2 + SIZE / 2) as usize][0];
        assert!(
            red <= previous_red,
            "horizon gradient folded at {elevation}"
        );
        assert!(image.iter().flatten().all(|v| v.is_finite()));
        previous_red = red;
    }
    assert!((previous_red - scene.sky_upper[0]).abs() < 1.2 / 255.0);
}

#[test]
fn authored_solar_samples_retain_native_visibility_and_missing_color_fallback() {
    let mut h = Harness::pair(VS_CELESTIAL, PS_CELESTIAL_SUN, false);
    // Decoded samples from DNWeathers.bsa textures/sky/sun.dds: center
    // (512,512), inner halo (550,512), outer halo (600,512), and transparent
    // border (100,100). Black is an additional authored boundary input.
    // No texture asset is redistributed.
    let samples = [0xFFE6DBBD, 0x9A6D6554, 0x753C372C, 0x40000000, 0x00FF0000];
    let input: Vec<_> = (0..SIZE * SIZE)
        .map(|i| samples[(i % SIZE / 7) as usize])
        .collect();
    h.image(&input, &input);
    let mut scene = frame();
    scene.sun_light = [0.0; 3];
    scene.sun_disk = [0.0; 3];
    let settings = NativeSkySettings::from(crate::config::NativeSkyConfig::default());
    for visibility in [0.0, 0.4, 1.0] {
        h.visibility = visibility;
        let image = h.draw_settings(scene, settings, 0.0);
        for (actual, encoded) in image.iter().zip(&input) {
            let channels = [
                ((encoded >> 16) & 255) as f32,
                ((encoded >> 8) & 255) as f32,
                (encoded & 255) as f32,
            ];
            for (value, authored) in actual[..3].iter().zip(channels) {
                assert!((*value - authored / 255.0).abs() < 0.002);
            }
            let alpha = ((encoded >> 24) & 255) as f32 / 255.0;
            assert!((actual[3] - alpha * visibility).abs() < 0.001);
        }
    }
}

#[test]
fn missing_sun_color_retains_ambient_flat_cloud_detail() {
    let h = Harness::new(false, false);
    let ramp: Vec<_> = (0..SIZE * SIZE)
        .map(|index| {
            let v = 96 + index % SIZE * 3;
            (224 << 24) | (v << 16) | (v << 8) | v
        })
        .collect();
    h.image(&ramp, &ramp);
    let mut scene = frame();
    scene.sun_direction = [1.0, 0.0, 0.0];
    scene.sun_light = scene.sky_upper;
    let ambient = h.draw(scene, 1.0, 0.0);
    scene.sun_light = [0.0; 3];
    scene.sun_disk = [0.0; 3];
    let missing = h.draw(scene, 1.0, 0.0);
    // Full coverage suppresses the separate solar-scattering term. A missing
    // optional sun candidate must leave the same existing ambient tint.
    for (reference, actual) in ambient.iter().zip(&missing) {
        for channel in 0..3 {
            assert!(
                (reference[channel] - actual[channel]).abs() < 0.002,
                "missing sun erased ambient detail: reference={reference:?}, actual={actual:?}"
            );
        }
    }
}

#[test]
fn cloud_brightness_is_one_linear_gain_with_unchanged_alpha() {
    for normals in [false, true] {
        let h = Harness::new(normals, false);
        let image = vec![0xBFB0_C0D0; (SIZE * SIZE) as usize];
        h.image(&image, &image);
        let mut scene = frame();
        scene.sun_direction = [0.866_025_4, 0.0, 0.5];
        let anchor = h.draw(scene, 1.0, 0.0);
        for gain in [0.0, 0.25, 0.5, 1.5, 2.0] {
            let output = h.draw(scene, gain, 0.0);
            for (a, b) in anchor.iter().zip(&output) {
                assert!((a[3] - b[3]).abs() < 0.001);
                for channel in 0..3 {
                    let expected = linearize_color([a[channel]; 3])[0] * gain;
                    let actual = linearize_color([b[channel]; 3])[0];
                    assert!(
                        (expected - actual).abs() < 0.006 * expected.max(1.0),
                        "brightness changed lighting: normals={normals}, gain={gain}, expected={expected}, actual={actual}"
                    );
                }
            }
        }
    }
}

#[test]
fn cloud_blending_preserves_authored_coverage_and_quantized_detail() {
    for normals in [false, true] {
        for quantized in [false, true] {
            let h = Harness::new(normals, quantized);
            let ramp: Vec<_> = (0..SIZE * SIZE)
                .map(|index| {
                    let x = index % SIZE;
                    let v = 48 + x * 4;
                    (192 << 24) | (v << 16) | (v << 8) | v
                })
                .collect();
            let second = vec![0x6000_0000; ramp.len()];
            h.image(&ramp, &second);
            for blend in [0.0, 0.25, 0.5, 0.75, 1.0] {
                let output = h.draw(frame(), 0.5, blend);
                let expected_alpha = (192.0 * (1.0 - blend) + 96.0 * blend) / 255.0;
                for p in &output {
                    assert!(p.iter().all(|v| v.is_finite() && *v >= 0.0));
                    assert!((p[3] - expected_alpha).abs() <= 1.0 / 255.0);
                }
                // The black-texture fallback retains RGB while alpha blends.
                // Flat textures carry authored RGB detail; normal-mode RGB has
                // another meaning and is deliberately not given that oracle.
                if !normals {
                    let row = &output[(SIZE * 16) as usize..(SIZE * 17) as usize];
                    assert!(row[27][0] > row[4][0] + 1.0 / 255.0);
                }
            }
        }
    }
}

#[test]
fn bright_ambient_cannot_make_direct_cloud_light_negative() {
    let h = Harness::new(true, false);
    let image = vec![0xBFBB_BBFF; (SIZE * SIZE) as usize];
    h.image(&image, &image);
    let mut scene = frame();
    scene.sky_upper = [3.0; 3];
    scene.sky_lower = [3.0; 3];
    scene.horizon = [3.0; 3];
    scene.sun_direction = [0.0, 0.0, -1.0];
    scene.sun_light = [0.0; 3];
    let ambient = h.draw(scene, 1.0, 0.0);
    scene.sun_light = [1.0; 3];
    let lit = h.draw(scene, 1.0, 0.0);
    let center = (SIZE * SIZE / 2 + SIZE / 2) as usize;
    for channel in 0..3 {
        assert!(
            lit[center][channel] + 0.002 >= ambient[center][channel],
            "direct sunlight subtracted cloud light: ambient={:?}, lit={:?}",
            ambient[center],
            lit[center]
        );
    }
}

#[test]
fn bright_cloud_detail_survives_production_final_tone_in_unorm() {
    use crate::{
        backend::FrameInputs,
        config::{AdaptiveToneConfig, EmbeddedEffectsConfig},
        effects::blooming_hdr::{BloomingHdrEffect, FinalColorShaderBytecode},
        render_state::RenderTargetSlots,
        shaders::EmbeddedEffectKind,
    };

    let h = Harness::new(false, false);
    let ramp: Vec<_> = (0..SIZE * SIZE)
        .map(|index| {
            let v = 176 + (index % SIZE) * 2;
            (191 << 24) | (v << 16) | (v << 8) | v
        })
        .collect();
    h.image(&ramp, &ramp);
    let row = (SIZE * 16) as usize;
    let device = h.owner.as_ref();
    let mut config = EmbeddedEffectsConfig::default();
    config.blooming_hdr.enabled = false;
    config.color_grade.color_grading_enabled = false;
    config.color_grade.lut_enabled = false;
    config.color_grade.deband_enabled = false;
    config.color_grade.film_grain_enabled = false;
    config.color_grade.vignette_enabled = false;
    config.color_grade.halation_enabled = false;
    config.color_grade.chromatic_aberration_enabled = false;
    let mut source = crate::shaders::merge_embedded_sources_with_luts_and_adaptive(
        &config,
        &AdaptiveToneConfig::default(),
        &[],
        &[],
        Vec::new(),
    )
    .into_iter()
    .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade))
    .unwrap();
    source.enabled = true;
    let mut effect = BloomingHdrEffect::create(
        &device,
        &FinalColorShaderBytecode::prepare().unwrap(),
        RenderTargetSlots::query(&device).unwrap(),
    )
    .unwrap();
    let output = device
        .create_render_target_texture(SIZE, SIZE, D3DFMT_A8R8G8B8)
        .unwrap();
    let surface = output.surface_level(0).unwrap();
    let memory = device
        .create_system_memory_surface(SIZE, SIZE, D3DFMT_A8R8G8B8)
        .unwrap();
    for elevation in [0.0f32, 0.5, 1.0] {
        let mut scene = frame();
        scene.sun_direction = [(1.0 - elevation * elevation).sqrt(), 0.0, elevation];
        for transparency in [
            1.0,
            crate::config::NativeSkyConfig::default().cloud_transparency,
        ] {
            let clouds = h.draw_with_transparency(scene, 2.0, 0.0, transparency);
            if elevation == 1.0 {
                assert!(
                    clouds[row + 27][0] > 1.0,
                    "fixture must exercise sky headroom"
                );
            }
            device.begin_scene().unwrap();
            assert!(
                effect
                    .draw(
                        &device,
                        &surface,
                        &surface.desc().unwrap(),
                        &FrameInputs::default(),
                        None,
                        Some(&source),
                        None,
                        &h.output,
                        0,
                        1.0 / 60.0,
                        false,
                        false
                    )
                    .unwrap()
            );
            device.end_scene().unwrap();
            device.copy_render_target_data(&surface, &memory).unwrap();
            let pixels = memory.read_rgba8().unwrap();
            assert!(
                pixels
                    .iter()
                    .flatten()
                    .all(|value| value.is_finite() && (0.0..=1.0).contains(value))
            );
            assert!(
                pixels[row + 27][0] > pixels[row + 4][0] + 1.0 / 255.0,
                "final tone erased bright cloud detail: dark={:?}, bright={:?}",
                pixels[row + 4],
                pixels[row + 27]
            );
        }
    }
}

#[test]
fn low_sun_colored_cloud_blends_retain_detail_at_shipped_transparency() {
    for normals in [false, true] {
        let h = Harness::new(normals, false);
        let first: Vec<_> = (0..SIZE * SIZE)
            .map(|i| {
                let x = i % SIZE;
                (192 << 24) | ((112 + x * 3) << 16) | ((100 + x * 2) << 8) | 96
            })
            .collect();
        let second: Vec<_> = (0..SIZE * SIZE)
            .map(|i| {
                let x = i % SIZE;
                (128 << 24) | ((80 + x * 2) << 16) | ((128 + x * 3) << 8) | 144
            })
            .collect();
        h.image(&first, &second);
        for elevation in [0.0f32, 0.5, 1.0] {
            let mut scene = frame();
            scene.sun_direction = [(1.0 - elevation * elevation).sqrt(), 0.0, elevation];
            for transparency in [
                1.0,
                crate::config::NativeSkyConfig::default().cloud_transparency,
            ] {
                for blend in [0.0, 0.25, 0.5, 0.75, 1.0] {
                    let anchor = h.draw_with_transparency(scene, 1.0, blend, transparency);
                    let half = h.draw_with_transparency(scene, 0.5, blend, transparency);
                    for (a, b) in anchor.iter().zip(&half) {
                        assert!(a.iter().all(|value| value.is_finite() && *value >= 0.0));
                        assert!((a[3] - b[3]).abs() < 0.001);
                        for channel in 0..3 {
                            let expected = linearize_color([a[channel]; 3])[0] * 0.5;
                            let actual = linearize_color([b[channel]; 3])[0];
                            assert!((expected - actual).abs() < 0.006 * expected.max(1.0));
                        }
                    }
                    if !normals {
                        let row = (SIZE * 16) as usize;
                        assert!(
                            anchor[row + 27][1] > anchor[row + 4][1] + 1.0 / 255.0,
                            "low-sun blend erased authored contrast: elevation={elevation}, blend={blend}, transparency={transparency}"
                        );
                    }
                }
            }
        }
    }
}

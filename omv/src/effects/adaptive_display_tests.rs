//! Controlled visual regressions through the shipped D3D9 final-color path.
//!
//! These fixtures are authorized visual-effect design inputs, not reconstructed
//! gameplay captures. The production compiler, constants, resources, history,
//! samplers and composition execute on the Wine D3D9 device; only input images
//! and elapsed frame intervals are supplied by the tests.

use super::*;
use crate::{config::EmbeddedEffectsConfig, shaders::EmbeddedEffectKind};
use libpsycho::os::windows::{directx9::*, winapi::get_desktop_window};

struct Harness {
    effect: BloomingHdrEffect,
    source: ScreenShaderSource,
    bloom: Option<ScreenShaderSource>,
    lut: Option<LutAsset>,
    input: Texture9,
    output: Texture9,
    readback: Surface9,
    owner: Device9,
    width: u32,
    height: u32,
}

impl Harness {
    fn new(width: u32, height: u32, adaptive: AdaptiveToneConfig) -> Self {
        let owner = create_direct3d9()
            .unwrap()
            .create_windowed_device(get_desktop_window().unwrap(), width, height, D3DDEVTYPE_HAL)
            .unwrap();
        let device = owner.as_ref();
        let mut config = EmbeddedEffectsConfig::default();
        config.blooming_hdr.enabled = false;
        config.color_grade.color_grading_enabled = false;
        config.color_grade.lut_enabled = false;
        config.color_grade.deband_enabled = false;
        config.color_grade.film_grain_enabled = false;
        config.color_grade.vignette_enabled = false;
        config.color_grade.halation_enabled = false;
        config.color_grade.chromatic_aberration_enabled = false;
        let mut source = shaders::merge_embedded_sources_with_luts_and_adaptive(
            &config,
            &adaptive,
            &[],
            &[],
            Vec::new(),
        )
        .into_iter()
        .find(|s| s.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade))
        .unwrap();
        source.enabled = true;
        let effect = BloomingHdrEffect::create(
            &device,
            &FinalColorShaderBytecode::prepare().unwrap(),
            RenderTargetSlots::query(&device).unwrap(),
        )
        .unwrap();
        assert!(
            effect.adaptive_pipeline.is_some(),
            "test requires FP16 adaptation"
        );
        let input =
            create_argb_texture(&device, width, height, &vec![0; (width * height) as usize])
                .unwrap();
        let output = device
            .create_render_target_texture(width, height, D3DFMT_A16B16G16R16F)
            .unwrap();
        let readback = device
            .create_system_memory_surface(width, height, D3DFMT_A16B16G16R16F)
            .unwrap();
        Self {
            effect,
            source,
            bloom: None,
            lut: None,
            input,
            output,
            readback,
            owner,
            width,
            height,
        }
    }

    fn image(&self, pixels: &[u32]) {
        self.input
            .write_level0_argb(self.width, self.height, pixels)
            .unwrap();
    }

    // Only the input generator is test-owned. All subsequent metering, history,
    // grading, LUT, response filtering, and output conversion remain shipped.
    fn highlight_ramp(&mut self, color: [f32; 3], start: f32, end: f32) {
        let device = self.owner.as_ref();
        self.input = hlsl_fill_ramp(&device, self.width, self.height, color, start, end);
    }

    fn unorm_output(&mut self) {
        let device = self.owner.as_ref();
        self.output = device
            .create_render_target_texture(self.width, self.height, D3DFMT_A8R8G8B8)
            .unwrap();
        self.readback = device
            .create_system_memory_surface(self.width, self.height, D3DFMT_A8R8G8B8)
            .unwrap();
    }

    fn option(&mut self, key: &str, value: ShaderOptionValue) {
        let index = self
            .source
            .options
            .iter()
            .position(|o| o.key == key)
            .unwrap();
        match value {
            ShaderOptionValue::Float(v) => self.source.set_option_float(index, v).unwrap(),
            ShaderOptionValue::Integer(v) => self.source.set_option_integer(index, v).unwrap(),
            ShaderOptionValue::Bool(v) => self.source.set_option_bool(index, v).unwrap(),
        }
    }

    fn frame(&mut self, continuous: bool, seconds: f32) {
        let device = self.owner.as_ref();
        let surface = self.output.surface_level(0).unwrap();
        device.begin_scene().unwrap();
        assert!(
            self.effect
                .draw(
                    &device,
                    &surface,
                    &surface.desc().unwrap(),
                    &FrameInputs::default(),
                    self.bloom.as_ref(),
                    Some(&self.source),
                    self.lut.as_ref(),
                    &self.input,
                    0,
                    seconds,
                    continuous,
                )
                .unwrap()
        );
        device.end_scene().unwrap();
    }

    fn pixels(&self) -> Vec<[f32; 4]> {
        self.owner
            .as_ref()
            .copy_render_target_data(&self.output.surface_level(0).unwrap(), &self.readback)
            .unwrap();
        if self.readback.desc().unwrap().Format == D3DFMT_A8R8G8B8 {
            self.readback.read_rgba8().unwrap()
        } else {
            self.readback.read_rgba16f().unwrap()
        }
    }

    fn history(&self) -> [f32; 4] {
        let device = self.owner.as_ref();
        let surface = self
            .effect
            .adaptive_history
            .as_ref()
            .unwrap()
            .current_texture()
            .surface_level(0)
            .unwrap();
        let memory = device
            .create_system_memory_surface(ADAPTIVE_RESPONSE_WIDTH, 1, D3DFMT_A16B16G16R16F)
            .unwrap();
        device.copy_render_target_data(&surface, &memory).unwrap();
        let pixels = memory.read_rgba16f().unwrap();
        let mut state = pixels[0];
        state[1] += pixels[1][1];
        state
    }
}

fn hlsl_fill_ramp(
    device: &Device9Ref<'_>,
    width: u32,
    height: u32,
    color: [f32; 3],
    start: f32,
    end: f32,
) -> Texture9 {
    hlsl_input(
        device,
        width,
        height,
        b"float4 Color:register(c0);float4 Range:register(c1);\
          float4 Main(float2 uv:TEXCOORD0):COLOR0{\
          return float4(Color.rgb*(Range.x+Range.y*uv.x),Color.a);}",
        &[
            [color[0], color[1], color[2], 0.5],
            [start, end - start, 0.0, 0.0],
        ],
    )
}

fn hlsl_input(
    device: &Device9Ref<'_>,
    width: u32,
    height: u32,
    source: &[u8],
    constants: &[[f32; 4]],
) -> Texture9 {
    let input = device
        .create_render_target_texture(width, height, D3DFMT_A16B16G16R16F)
        .unwrap();
    let fill = device
        .create_pixel_shader(
            &shaders::compile_hlsl_source_target("adaptive_highlight_input.hlsl", source, "ps_3_0")
                .unwrap(),
        )
        .unwrap();
    bind_pipeline_state(device).unwrap();
    device.clear_texture(7).unwrap();
    bind_target(
        device,
        &input.surface_level(0).unwrap(),
        width,
        height,
        RenderTargetSlots::query(device).unwrap(),
    )
    .unwrap();
    device.set_pixel_shader(&fill).unwrap();
    device.set_pixel_shader_constant_f(0, constants).unwrap();
    device.begin_scene().unwrap();
    draw_quad(device, width, height).unwrap();
    device.end_scene().unwrap();
    input
}

fn assert_highlight_detail(pixels: &[[f32; 4]], width: usize, context: &str) {
    let row = &pixels[..width];
    assert!(
        luma(row[width - 1]) > luma(row[width / 2]) && luma(row[width / 2]) > luma(row[0]),
        "highlight levels collapsed ({context}): {:?}, {:?}, {:?}",
        row[0],
        row[width / 2],
        row[width - 1]
    );
    for pair in row.windows(2) {
        assert!(
            luma(pair[1]) + 0.001 >= luma(pair[0]),
            "ramp folded ({context}): {pair:?}"
        );
    }
    for p in pixels {
        assert!(p.iter().all(|v| v.is_finite() && (0.0..=1.0).contains(v)));
        assert!(
            (p[3] - 0.5).abs() <= 1.0 / 255.0,
            "alpha changed ({context})"
        );
    }
}

#[test]
fn colored_highlights_retain_detail_in_fixed_automatic_and_quantized_output() {
    let mut h = Harness::new(
        512,
        8,
        AdaptiveToneConfig {
            auto_exposure_enabled: false,
            ..AdaptiveToneConfig::default()
        },
    );
    for quantized in [false, true] {
        if quantized {
            h.unorm_output();
        }
        for mode in [ToneMapperMode::Neutral, ToneMapperMode::Automatic] {
            h.option("tone_mapper_mode", ShaderOptionValue::Integer(mode.index()));
            for color in [
                [0.25, 0.5, 1.0],
                [0.25, 1.0, 1.0],
                [1.0, 0.5, 0.25],
                [1.0; 3],
            ] {
                h.highlight_ramp(color, 1.0, 4.0);
                h.frame(false, 1.0 / 60.0);
                assert_highlight_detail(
                    &h.pixels(),
                    512,
                    &format!("initial {mode:?}, UNORM={quantized}, color={color:?}"),
                );
                for _ in 0..180 {
                    h.frame(true, 1.0 / 60.0);
                }
                let pixels = h.pixels();
                assert_highlight_detail(&pixels, 512, "settled response");
                if !quantized {
                    for p in &pixels {
                        assert!((p[1] / p[0] - color[1] / color[0]).abs() < 0.01);
                        assert!((p[2] / p[0] - color[2] / color[0]).abs() < 0.01);
                    }
                }
            }
        }
    }
}

#[test]
fn analytic_grading_preserves_over_white_detail_at_saved_and_full_strength() {
    let mut h = Harness::new(
        512,
        8,
        AdaptiveToneConfig {
            auto_exposure_enabled: false,
            ..AdaptiveToneConfig::default()
        },
    );
    h.highlight_ramp([1.0; 3], 1.0, 4.0);
    h.option("color_grading_enabled", ShaderOptionValue::Bool(true));
    for strength in [0.68, 1.0] {
        h.option("strength", ShaderOptionValue::Float(strength));
        h.frame(false, 1.0 / 60.0);
        assert_highlight_detail(&h.pixels(), 512, "analytic grading FP16");
    }
    h.unorm_output();
    h.frame(false, 1.0 / 60.0);
    assert_highlight_detail(&h.pixels(), 512, "analytic grading UNORM");
}

#[test]
fn display_luts_preserve_over_white_detail_at_full_lut_strength() {
    let mut h = Harness::new(
        512,
        8,
        AdaptiveToneConfig {
            auto_exposure_enabled: false,
            ..AdaptiveToneConfig::default()
        },
    );
    h.option("strength", ShaderOptionValue::Float(1.0));
    h.option("lut_enabled", ShaderOptionValue::Bool(true));
    h.option("lut_strength", ShaderOptionValue::Float(1.0));
    for name in ["00_neutral.cube", "01_mojave_natural.cube"] {
        h.lut = crate::luts::shipped_luts_for_test()
            .into_iter()
            .find(|lut| lut.file_name == name);
        assert!(h.lut.is_some());
        h.highlight_ramp([1.0; 3], 1.0, 4.0);
        h.frame(false, 1.0 / 60.0);
        assert_highlight_detail(&h.pixels(), 512, name);
    }
    h.unorm_output();
    h.frame(false, 1.0 / 60.0);
    assert_highlight_detail(&h.pixels(), 512, "Mojave Natural UNORM");
}

#[test]
fn highlights_beyond_old_table_domain_remain_ordered_and_match_fixed_mapping() {
    let mut h = Harness::new(
        512,
        8,
        AdaptiveToneConfig {
            tone_mapper_strength: 3.0,
            tone_mapper_mode: ToneMapperMode::Neutral,
            ..AdaptiveToneConfig::default()
        },
    );
    h.highlight_ramp([0.25, 0.5, 1.0], 4.0, 16.0);
    h.frame(false, 1.0 / 60.0);
    let filtered = h.pixels();
    assert_highlight_detail(&filtered, 512, "4..16 filtered FP16");
    h.option("auto_exposure_enabled", ShaderOptionValue::Bool(false));
    h.frame(false, 1.0 / 60.0);
    let fixed = h.pixels();
    assert_highlight_detail(&fixed, 512, "4..16 fixed FP16");
    for (a, b) in filtered.iter().zip(&fixed) {
        for c in 0..3 {
            assert!((a[c] - b[c]).abs() < 0.002);
        }
    }
    h.unorm_output();
    for mode in [ToneMapperMode::Neutral, ToneMapperMode::Automatic] {
        h.option("tone_mapper_mode", ShaderOptionValue::Integer(mode.index()));
        for frame in 0..180 {
            h.frame(frame != 0, 1.0 / 60.0);
        }
        assert_highlight_detail(&h.pixels(), 512, "4..16 UNORM");
    }
}

#[test]
fn active_highlights_preserve_sky_brightness_at_every_strength_and_coverage() {
    let mut h = Harness::new(
        64,
        64,
        AdaptiveToneConfig {
            auto_exposure_enabled: false,
            ..AdaptiveToneConfig::default()
        },
    );
    for strength in [0.1, 0.6761261, 1.0, 3.0] {
        h.option("tone_mapper_strength", ShaderOptionValue::Float(strength));
        let mut previous: Option<[f32; 4]> = None;
        for bright_rows in [1, 8, 16] {
            h.input = hlsl_input(
                &h.owner.as_ref(),
                64,
                64,
                b"float4 Coverage:register(c0);\
                  float4 Main(float2 uv:TEXCOORD0):COLOR0{\
                  float value=uv.y<Coverage.x?2.0:(uv.y<0.5?0.8:0.3);\
                  return float4(value.xxx,0.5);}",
                &[[bright_rows as f32 / 64.0, 0.0, 0.0, 0.0]],
            );
            for frame in 0..180 {
                h.frame(frame != 0, 1.0 / 60.0);
            }
            let output = h.pixels();
            let sky = output[64 * 24];
            let ground = output[64 * 48];
            assert!(h.history()[3] > 0.99);
            assert!(
                luma(sky) >= 0.8 - 1.0 / 255.0,
                "active shoulder dulled sky: {sky:?}"
            );
            assert!(luma(ground) < 0.3);
            assert!(luma(sky) / luma(ground) > 0.8 / 0.3);
            if let Some(old) = previous {
                assert!((old[0] - sky[0]).abs() < 0.001);
            }
            previous = Some(sky);
        }
    }
}

fn luma(pixel: [f32; 4]) -> f32 {
    pixel[0] * 0.2126 + pixel[1] * 0.7152 + pixel[2] * 0.0722
}

#[test]
fn mixed_views_retain_bright_sky_dark_ground_and_stable_tone() {
    let mut h = Harness::new(
        64,
        64,
        AdaptiveToneConfig {
            auto_exposure_enabled: false,
            tone_mapper_strength: 0.6761261,
            ..AdaptiveToneConfig::default()
        },
    );
    let mut previous: Option<(f32, f32)> = None;
    for sky_rows in [48, 32, 26] {
        let pixels: Vec<_> = (0..64 * 64)
            .map(|i| {
                if i / 64 < sky_rows {
                    0xFFCCCCCC
                } else {
                    0xFF4D4D4D
                }
            })
            .collect();
        h.image(&pixels);
        for frame in 0..360 {
            h.frame(frame != 0, 1.0 / 60.0);
        }
        let result = h.pixels();
        let sky = luma(result[0]);
        let ground = luma(*result.last().unwrap());
        assert!(
            sky >= 0.80 - 1.0 / 255.0,
            "sky became dull at {sky_rows}/64 coverage: {sky}"
        );
        assert!(ground < 77.0 / 255.0, "ground was lifted: {ground}");
        assert!(
            sky / ground > 204.0 / 77.0,
            "brightness separation was compressed"
        );
        if let Some((old_sky, old_ground)) = previous {
            assert!(
                (sky - old_sky).abs() < 2.0 / 255.0 && (ground - old_ground).abs() < 2.0 / 255.0,
                "sky occupancy changed the settled rendering"
            );
        }
        previous = Some((sky, ground));
    }
}

#[test]
fn horizon_crossing_old_sample_row_does_not_jump_meter() {
    let mut h = Harness::new(
        256,
        256,
        AdaptiveToneConfig {
            tone_mapper_mode: ToneMapperMode::Off,
            ..AdaptiveToneConfig::default()
        },
    );
    let mut means = Vec::new();
    for sky_rows in [95, 97] {
        let pixels: Vec<_> = (0..256 * 256)
            .map(|i| {
                if i / 256 < sky_rows {
                    0xFFCCCCCC
                } else {
                    0xFF333333
                }
            })
            .collect();
        h.image(&pixels);
        h.frame(false, 1.0 / 60.0);
        means.push(h.history()[1]);
    }
    assert!(
        (means[1] - means[0]).abs() < 0.10,
        "two rows of camera coverage caused a large exposure step: {means:?}"
    );
}

#[test]
fn looking_toward_ground_does_not_dim_existing_bright_surfaces() {
    for quantized in [false, true] {
        for (range, speed) in [(0.75, 1.0), (0.4189329, 0.4819511), (3.0, 1.0)] {
            let mut h = Harness::new(
                64,
                64,
                AdaptiveToneConfig {
                    exposure_range_ev: range,
                    adaptation_speed: speed,
                    tone_mapper_strength: 0.6761261,
                    ..AdaptiveToneConfig::default()
                },
            );
            if quantized {
                h.unorm_output();
            }
            let image = |sky_rows| {
                (0..64 * 64)
                    .map(|i| {
                        if i / 64 < sky_rows {
                            0xFFB3B3B3
                        } else {
                            0xFF4D4D4D
                        }
                    })
                    .collect::<Vec<_>>()
            };
            h.image(&image(48));
            h.frame(false, 1.0 / 60.0);
            let anchor = h.pixels()[0];
            for sky_rows in [26, 16, 8] {
                h.image(&image(sky_rows));
                let mut strongest_response = 0.0f32;
                for _ in 0..90 {
                    h.frame(true, 1.0 / 60.0);
                    let pixels = h.pixels();
                    strongest_response = strongest_response.min(h.history()[2]);
                    assert!(pixels.iter().flatten().all(|value| value.is_finite()));
                    assert!(
                        (luma(pixels[0]) - luma(anchor)).abs() < 2.0 / 255.0,
                        "ground coverage dimmed unchanged sky: rows={sky_rows}, range={range}, speed={speed}, quantized={quantized}, anchor={anchor:?}, sky={:?}, history={:?}",
                        pixels[0],
                        h.history()
                    );
                }
                assert!(
                    strongest_response < -0.035,
                    "fixture did not exercise negative adaptation: {strongest_response}"
                );
            }
        }
    }
}

#[test]
fn negative_adaptation_retains_bright_gradients_hue_and_dark_response() {
    for quantized in [false, true] {
        for mode in [
            ToneMapperMode::Off,
            ToneMapperMode::Neutral,
            ToneMapperMode::Automatic,
        ] {
            for strength in [0.0, 0.65, 3.0] {
                let mut h = Harness::new(
                    256,
                    32,
                    AdaptiveToneConfig {
                        exposure_range_ev: 3.0,
                        tone_mapper_mode: mode,
                        tone_mapper_strength: strength,
                        ..AdaptiveToneConfig::default()
                    },
                );
                if quantized {
                    h.unorm_output();
                }
                // The top strip contains an unchanged display gradient. Dark
                // ground below it drives strong negative temporal adaptation.
                let image: Vec<_> = (0..256 * 32)
                    .map(|i| {
                        let v = if i / 256 < 4 { i % 256 } else { 26 };
                        0x7F000000 | (v << 16) | (v << 8) | v
                    })
                    .collect();
                h.image(&image);
                h.frame(false, 1.0 / 60.0);
                let neutral = h.pixels();
                h.image(&vec![0x7FCCCCCC; 256 * 32]);
                h.frame(false, 1.0 / 60.0);
                h.image(&image);
                for _ in 0..30 {
                    h.frame(true, 1.0 / 60.0);
                }
                assert!(
                    h.history()[2] < -0.5,
                    "fixture did not exercise strong adaptation"
                );
                let active = h.pixels();
                for pair in active[..256].windows(2) {
                    assert!(
                        pair[1][0] >= pair[0][0],
                        "bright relief folded the response: {pair:?}"
                    );
                }
                // Protect the wider bright range, including less intense sky
                // and colored surfaces, without flattening its gradient.
                for index in 179..256 {
                    assert!(
                        (active[index][0] - neutral[index][0]).abs() < 2.0 / 255.0,
                        "bright gradient changed during negative adaptation: index={index}, active={:?}, neutral={:?}",
                        active[index],
                        neutral[index]
                    );
                }
                assert!(
                    active[77][0] < neutral[77][0] - 0.005,
                    "protection removed the dark adaptation response"
                );
                assert!(active.iter().all(|p| {
                    p.iter().all(|v| v.is_finite() && (0.0..=1.0).contains(v))
                        && (p[3] - 127.0 / 255.0).abs() < 0.001
                }));
            }
        }
    }
    // A channel peak, rather than luminance, owns the scalar display response.
    // Thus saturated bright artwork retains its color ratios as well as value.
    for color in [
        0x7FB3B3B3, 0x7FBFBFBF, 0x7FCC8050, 0x7F809ACC, 0x7FB38050, 0x7F809AB3,
    ] {
        let mut h = Harness::new(64, 64, AdaptiveToneConfig::default());
        h.image(&vec![color; 64 * 64]);
        h.frame(false, 1.0 / 60.0);
        let anchor = h.pixels()[0];
        let image: Vec<_> = (0..64 * 64)
            .map(|i| if i / 64 < 16 { color } else { 0x7F333333 })
            .collect();
        h.image(&image);
        for _ in 0..30 {
            h.frame(true, 1.0 / 60.0);
        }
        assert!(h.history()[2] < -0.1);
        let current = h.pixels()[0];
        for channel in 0..3 {
            assert!((current[channel] - anchor[channel]).abs() < 2.0 / 255.0);
        }
    }
}

#[test]
fn negative_adaptation_keeps_over_range_shoulder_and_sky_stable() {
    let mut h = Harness::new(64, 64, AdaptiveToneConfig::default());
    let fill = |h: &Harness, rows: f32| {
        hlsl_input(
            &h.owner.as_ref(),
            64,
            64,
            b"float4 Coverage:register(c0);float4 Main(float2 uv:TEXCOORD0):COLOR0{\
          float value=uv.y<0.0625?2.0:(uv.y<Coverage.x?0.8:0.3);\
          return float4(value.xxx,0.5);}",
            &[[rows / 64.0, 0.0, 0.0, 0.0]],
        )
    };
    h.input = fill(&h, 48.0);
    for frame in 0..180 {
        h.frame(frame != 0, 1.0 / 60.0);
    }
    let anchor = h.pixels();
    assert!(h.history()[3] > 0.99);
    for rows in [26.0, 16.0, 8.0] {
        h.input = fill(&h, rows);
        let mut most_negative = 0.0f32;
        for _ in 0..60 {
            h.frame(true, 1.0 / 60.0);
            most_negative = most_negative.min(h.history()[2]);
            assert!(
                h.history()[3] > 0.99,
                "negative gain released highlight headroom"
            );
            let pixels = h.pixels();
            for index in [0, 64 * 6] {
                assert!(
                    (pixels[index][0] - anchor[index][0]).abs() < 2.0 / 255.0,
                    "unchanged highlight changed with framing: rows={rows}, anchor={:?}, current={:?}",
                    anchor[index],
                    pixels[index]
                );
            }
        }
        assert!(most_negative < -0.035);
    }
}

#[test]
fn every_strength_is_monotonic_hue_safe_and_matches_fixed_fallback() {
    let mut h = Harness::new(256, 8, AdaptiveToneConfig::default());
    let gradient: Vec<_> = (0..256 * 8)
        .map(|i| {
            let v = i % 256;
            0x7F000000 | (v << 16) | (v << 8) | v
        })
        .collect();
    h.image(&gradient);
    for strength in [0.0, 0.1, 0.65, 1.0, 2.0, 3.0] {
        h.option("tone_mapper_strength", ShaderOptionValue::Float(strength));
        h.option(
            "tone_mapper_mode",
            ShaderOptionValue::Integer(ToneMapperMode::Neutral.index()),
        );
        // Active exposure with neutral mode must still apply the fixed curve.
        h.frame(false, 1.0 / 60.0);
        let adaptive = h.pixels();
        if strength > 0.0 {
            h.option("auto_exposure_enabled", ShaderOptionValue::Bool(false));
            h.frame(false, 1.0 / 60.0);
            let fixed = h.pixels();
            for (a, b) in adaptive.iter().zip(&fixed) {
                assert!(
                    (a[0] - b[0]).abs() < 0.002,
                    "filtered curve diverged from fixed at {strength}: {a:?} {b:?}"
                );
            }
            h.option("auto_exposure_enabled", ShaderOptionValue::Bool(true));
        }
        assert_eq!(adaptive[0][0], 0.0);
        for pair in adaptive[..256].windows(2) {
            assert!(
                pair[1][0] >= pair[0][0],
                "curve folded at strength {strength}: {pair:?}"
            );
        }
        for p in &adaptive {
            assert!(p.iter().all(|v| v.is_finite() && (0.0..=1.0).contains(v)));
            assert!((p[3] - 127.0 / 255.0).abs() < 0.001, "alpha changed");
        }
        if strength == 0.0 {
            assert!((adaptive[204][0] - 0.80).abs() < 0.001);
        } else {
            assert!(adaptive[77][0] < 77.0 / 255.0 && adaptive[204][0] > 0.80);
        }
    }
    h.option("tone_mapper_strength", ShaderOptionValue::Float(3.0));
    for argb in [0xFF99BBFF, 0xFFFF8844, 0xFF22FF33] {
        h.image(&vec![argb; 256 * 8]);
        h.frame(false, 1.0 / 60.0);
        let output = h.pixels()[0];
        let input = [
            (argb >> 16 & 255) as f32,
            (argb >> 8 & 255) as f32,
            (argb & 255) as f32,
        ];
        assert!((output[1] / output[0] - input[1] / input[0]).abs() < 0.01);
        assert!((output[2] / output[0] - input[2] / input[0]).abs() < 0.01);
    }
}

#[test]
fn exposure_history_is_bounded_converges_and_survives_black_and_gaps() {
    let mut h = Harness::new(32, 32, AdaptiveToneConfig::default());
    let mut at_one_second = Vec::new();
    for hz in [30, 60, 120, 144] {
        h.image(&vec![0xFF4D4D4D; 32 * 32]);
        h.frame(false, 1.0 / hz as f32);
        assert_eq!(h.history()[2], 0.0, "first image must seed neutrally");
        h.image(&vec![0xFFCCCCCC; 32 * 32]);
        for _ in 0..hz {
            h.frame(true, 1.0 / hz as f32);
        }
        let ev = h.history()[2];
        assert!(ev > 0.0 && ev <= 0.75, "unexpected bright transition: {ev}");
        at_one_second.push(ev);
        for _ in 0..hz * 14 {
            h.frame(true, 1.0 / hz as f32);
        }
        assert!(
            h.history()[2].abs() < 0.01,
            "settled view retained exposure: {:?}",
            h.history()
        );
        h.image(&vec![0xFF4D4D4D; 32 * 32]);
        for _ in 0..hz {
            h.frame(true, 1.0 / hz as f32);
        }
        assert!(h.history()[2] < 0.0 && h.history()[2] >= -0.75);
        let held = h.history();
        h.image(&vec![0xFF000000; 32 * 32]);
        h.frame(true, 1.0 / hz as f32);
        assert_eq!(&h.history()[1..], &held[1..]);
        assert_eq!(h.pixels()[0][0], 0.0);
        h.frame(false, 1.0 / hz as f32);
        assert_eq!(h.history()[2], 0.0);
        h.image(&vec![0xFF808080; 32 * 32]);
        h.frame(true, 1.0 / hz as f32);
        assert_eq!(h.history()[2], 0.0, "black/gap seeded stale adaptation");
    }
    let low = at_one_second.iter().copied().fold(f32::INFINITY, f32::min);
    let high = at_one_second
        .iter()
        .copied()
        .fold(f32::NEG_INFINITY, f32::max);
    assert!(
        high - low < 0.03,
        "frame-rate dependent exposure: {at_one_second:?}"
    );
}

#[test]
fn saved_slow_speed_settles_to_neutral_in_dark_views() {
    let mut h = Harness::new(
        32,
        32,
        AdaptiveToneConfig {
            exposure_range_ev: 0.4189329,
            adaptation_speed: 0.4819511,
            ..AdaptiveToneConfig::default()
        },
    );
    for speed in [0.4819511, 0.1, 4.0] {
        h.option("adaptation_speed", ShaderOptionValue::Float(speed));
        h.image(&vec![0xFFCCCCCC; 32 * 32]);
        h.frame(false, 1.0 / 60.0);
        h.image(&vec![0xFF333333; 32 * 32]);
        for _ in 0..(60.0 * 22.0 / speed) as u32 {
            h.frame(true, 1.0 / 60.0);
        }
        assert!(
            h.history()[2].abs() < 0.01,
            "FP16 history left a persistent correction at speed {speed}: {:?}",
            h.history()
        );
    }
}

#[test]
fn over_range_highlights_drive_only_shoulder_and_release_smoothly() {
    let mut h = Harness::new(
        64,
        32,
        AdaptiveToneConfig {
            auto_exposure_enabled: false,
            ..AdaptiveToneConfig::default()
        },
    );
    // FP16 render target is a real production input format. Populate the input
    // with a compiled constant shader to exercise values beyond UNORM8 white.
    let device = h.owner.as_ref();
    h.input = device
        .create_render_target_texture(64, 32, D3DFMT_A16B16G16R16F)
        .unwrap();
    let fill = device.create_pixel_shader(&shaders::compile_hlsl_source_target(
        "adaptive_test_input.hlsl", b"float4 Value:register(c0); float4 Main(float2 uv:TEXCOORD0):COLOR0{return Value;}", "ps_3_0",
    ).unwrap()).unwrap();
    let fill_input = |h: &Harness, value: f32| {
        let device = h.owner.as_ref();
        bind_pipeline_state(&device).unwrap();
        device.clear_texture(7).unwrap();
        bind_target(
            &device,
            &h.input.surface_level(0).unwrap(),
            64,
            32,
            RenderTargetSlots::query(&device).unwrap(),
        )
        .unwrap();
        device.set_pixel_shader(&fill).unwrap();
        device
            .set_pixel_shader_constant_f(0, &[[value, value, value, 1.0]])
            .unwrap();
        device.begin_scene().unwrap();
        draw_quad(&device, 64, 32).unwrap();
        device.end_scene().unwrap();
    };
    fill_input(&h, 0.8);
    h.frame(false, 1.0 / 60.0);
    fill_input(&h, 1.5);
    h.frame(true, 1.0 / 60.0);
    let onset = h.history()[3];
    assert!(onset > 0.0 && onset < 0.1);
    for _ in 0..180 {
        h.frame(true, 1.0 / 60.0);
    }
    let settled = h.history()[3];
    assert!(settled > 0.45 && settled < 0.55);
    let pixel = h.pixels()[0];
    assert!(
        pixel[0] > 0.9 && pixel[0] < 1.0,
        "over-white detail clipped: {pixel:?}"
    );
    fill_input(&h, 0.8);
    h.frame(true, 1.0 / 60.0);
    let release = h.history()[3];
    assert!(release < settled && release > settled - 0.02);
    for _ in 0..600 {
        h.frame(true, 1.0 / 60.0);
    }
    assert!(h.history()[3] < 0.001);
    assert!(h.pixels()[0][0] >= 0.8);
}

#[test]
fn bloom_and_creative_finishing_remain_bounded_and_independent() {
    let mut h = Harness::new(
        65,
        35,
        AdaptiveToneConfig {
            auto_exposure_enabled: false,
            ..AdaptiveToneConfig::default()
        },
    );
    let mut config = EmbeddedEffectsConfig::default();
    config.blooming_hdr.bloom_intensity = 1.5;
    config.blooming_hdr.highlight_shoulder = 0.0;
    config.blooming_hdr.bright_threshold = 0.4;
    config.blooming_hdr.dither = 0.0;
    let mut bloom = shaders::merge_embedded_sources(&config, Vec::new())
        .into_iter()
        .find(|s| s.embedded_effect_kind() == Some(EmbeddedEffectKind::BloomingHdr))
        .unwrap();
    bloom.enabled = true;
    h.bloom = Some(bloom);
    // Actual extraction, blur and composition create the over-range input.
    h.image(&vec![0xFFFFFFFF; 65 * 35]);
    for frame in 0..180 {
        h.frame(frame != 0, 1.0 / 60.0);
    }
    assert!(
        h.history()[3] > 0.0,
        "Bloom failed to engage automatic headroom"
    );
    let output = h.pixels();
    assert!(output.iter().all(|p| p[0] > 0.9 && p[0] < 1.0));

    h.lut = crate::luts::shipped_luts_for_test().into_iter().next();
    h.option("lut_enabled", ShaderOptionValue::Bool(true));
    h.option("color_grading_enabled", ShaderOptionValue::Bool(true));
    h.option("halation_enabled", ShaderOptionValue::Bool(true));
    h.option("vignette_enabled", ShaderOptionValue::Bool(true));
    let mut pixels = vec![0xFF4D4D4D; 65 * 35];
    pixels[..65 * 14].fill(0xFFCCCCCC);
    h.image(&pixels);
    h.frame(false, 1.0 / 60.0);
    let graded = h.pixels();
    assert!(
        graded
            .iter()
            .flatten()
            .all(|v| v.is_finite() && (0.0..=1.0).contains(v))
    );
    assert!(luma(graded[32]) > luma(graded[65 * 34 + 32]));
    h.bloom = None;
    h.option("strength", ShaderOptionValue::Float(0.0));
    h.frame(false, 1.0 / 60.0);
    let independent = h.pixels();
    assert!(luma(independent[32]) > 0.8 && luma(independent[65 * 34 + 32]) < 77.0 / 255.0);
    // Unsupported adaptation falls back to the same fixed curve, with creative
    // grading still independently disabled. Exercise the actual fallback route.
    h.effect.adaptive_pipeline = None;
    h.frame(false, 1.0 / 60.0);
    let fallback = h.pixels();
    for (a, b) in independent.iter().zip(&fallback) {
        assert!((a[0] - b[0]).abs() < 0.002);
    }
}

#[test]
fn disabled_path_allocates_no_meter_and_resize_restarts_neutrally() {
    let mut h = Harness::new(
        32,
        32,
        AdaptiveToneConfig {
            auto_exposure_enabled: false,
            tone_mapper_mode: ToneMapperMode::Off,
            ..AdaptiveToneConfig::default()
        },
    );
    let surface = h.output.surface_level(0).unwrap();
    assert!(
        !h.effect
            .draw(
                &h.owner.as_ref(),
                &surface,
                &surface.desc().unwrap(),
                &FrameInputs::default(),
                None,
                Some(&h.source),
                None,
                &h.input,
                0,
                1.0 / 60.0,
                false
            )
            .unwrap()
    );
    assert!(h.effect.adaptive_history.is_none());
    assert!(
        h.effect
            .adaptive_pipeline
            .as_ref()
            .unwrap()
            .resources
            .targets
            .is_none()
    );
    h.option("auto_exposure_enabled", ShaderOptionValue::Bool(true));
    h.image(&vec![0xFF333333; 32 * 32]);
    h.frame(false, 1.0 / 60.0);
    h.image(&vec![0xFFCCCCCC; 32 * 32]);
    for _ in 0..20 {
        h.frame(true, 1.0 / 60.0);
    }
    assert!(h.history()[2] > 0.0);
    let device = h.owner.as_ref();
    h.width = 33;
    h.height = 17;
    h.input = create_argb_texture(&device, 33, 17, &vec![0xFF4D4D4D; 33 * 17]).unwrap();
    h.output = device
        .create_render_target_texture(33, 17, D3DFMT_A16B16G16R16F)
        .unwrap();
    h.readback = device
        .create_system_memory_surface(33, 17, D3DFMT_A16B16G16R16F)
        .unwrap();
    h.frame(true, 1.0 / 60.0);
    assert_eq!(h.history()[2], 0.0);
    assert!((h.pixels()[0][0] - 77.0 / 255.0).abs() < 0.001);
}

#[test]
fn over_range_ramp_retains_detail_through_full_response_domain() {
    let mut h = Harness::new(512, 8, AdaptiveToneConfig::default());
    let device = h.owner.as_ref();
    h.input = device
        .create_render_target_texture(512, 8, D3DFMT_A16B16G16R16F)
        .unwrap();
    let fill = device
        .create_pixel_shader(
            &shaders::compile_hlsl_source_target(
                "adaptive_test_ramp.hlsl",
                b"float4 Main(float2 uv:TEXCOORD0):COLOR0{return float4((uv.x*4.0).xxx,1.0);}",
                "ps_3_0",
            )
            .unwrap(),
        )
        .unwrap();
    bind_pipeline_state(&device).unwrap();
    bind_target(
        &device,
        &h.input.surface_level(0).unwrap(),
        512,
        8,
        RenderTargetSlots::query(&device).unwrap(),
    )
    .unwrap();
    device.set_pixel_shader(&fill).unwrap();
    device.begin_scene().unwrap();
    draw_quad(&device, 512, 8).unwrap();
    device.end_scene().unwrap();
    for strength in [0.0001, 0.1, 0.65, 1.0, 2.0, 3.0] {
        h.option("tone_mapper_strength", ShaderOptionValue::Float(strength));
        h.option(
            "tone_mapper_mode",
            ShaderOptionValue::Integer(ToneMapperMode::Neutral.index()),
        );
        h.option("auto_exposure_enabled", ShaderOptionValue::Bool(true));
        h.frame(false, 1.0 / 60.0);
        let automatic = h.pixels();
        h.option("auto_exposure_enabled", ShaderOptionValue::Bool(false));
        h.frame(false, 1.0 / 60.0);
        let fixed = h.pixels();
        for pair in automatic[..512].windows(2) {
            assert!(
                pair[1][0] + 0.001 >= pair[0][0],
                "over-range curve folded at {strength}: {pair:?}"
            );
        }
        for (a, b) in automatic.iter().zip(&fixed) {
            assert!(a.iter().all(|v| v.is_finite() && (0.0..=1.0).contains(v)));
            assert!(
                (a[0] - b[0]).abs() < 0.002,
                "over-range lookup error at {strength}: {a:?} {b:?}"
            );
        }
        if strength >= 0.1 {
            assert!(
                automatic[127][0] < automatic[255][0] && automatic[255][0] < automatic[511][0],
                "highlight levels collapsed at {strength}"
            );
        }
    }
}

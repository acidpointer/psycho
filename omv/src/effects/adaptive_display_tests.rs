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
        self.readback.read_rgba16f().unwrap()
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

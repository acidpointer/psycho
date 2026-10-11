// GPU behavior and bytecode work gates for the shipped sunlight pass graph.
// Oracles execute the retained production HLSL, including its FP16 targets;
// no CPU implementation of reduction, extinction or reconstruction is used.

fn sun_work_bytecode_counts(code: &[u32]) -> (usize, usize) {
    assert_eq!(code[0], 0xffff_0300);
    let mut offset = 1;
    let mut instructions = 0;
    let mut textures = 0;
    let mut loops = 0;
    let mut branches = 0;
    while code[offset] as u16 != 0xffff {
        let token = code[offset];
        let opcode = token as u16;
        if opcode == 0xfffe {
            offset += 1 + ((token >> 16) & 0x7fff) as usize;
            continue;
        }
        assert!(!matches!(opcode, 25 | 26 | 30 | 91 | 92));
        match opcode {
            27 | 38 => loops += 1,
            29 | 39 => loops -= 1,
            40 | 41 => branches += 1,
            43 => branches -= 1,
            _ => {}
        }
        assert!(
            loops >= 0 && branches >= 0,
            "sun shader flow-control balance"
        );
        let length = ((token >> 24) & 0xf) as usize;
        for (index, operand) in code[offset + 1..offset + 1 + length].iter().enumerate() {
            if (matches!(opcode, 48 | 81 | 82) && index > 0)
                || (opcode == 31 && index == 0)
                || operand & 0x8000_0000 == 0
            {
                continue;
            }
            let kind = ((operand >> 28) & 7) | ((operand >> 8) & 0x18);
            let register = operand & 0x7ff;
            match kind {
                0 => assert!(register < 32, "sun work temporary budget"),
                2 => assert!(register < 224, "sun work constant budget"),
                10 => assert!(register < 7, "sun work sampler budget"),
                _ => {}
            }
        }
        instructions += 1;
        textures += usize::from(matches!(opcode, 66 | 93 | 95));
        offset += 1 + length;
        assert!(offset < code.len());
    }
    assert_eq!((loops, branches), (0, 0));
    (instructions, textures)
}

fn sun_work_readback(device: &Device9Ref<'_>, texture: &Texture9) -> Vec<[f32; 4]> {
    let surface = texture.surface_level(0).unwrap();
    let desc = surface.desc().unwrap();
    let readback = device
        .create_system_memory_surface(desc.Width, desc.Height, D3DFMT_A16B16G16R16F)
        .unwrap();
    device.copy_render_target_data(&surface, &readback).unwrap();
    readback.read_rgba16f().unwrap()
}

// read_rgba16f expands the actual FP16 storage value exactly to f32. Normal
// FP16 neighbors are 8192 f32 bit positions apart, including exponent edges;
// subnormal FP16 storage instead has a constant 2^-24 step.
fn sun_work_adjacent_fp16(reference: f32, actual: f32) -> bool {
    if reference.abs().min(actual.abs()) < 0.000_061_035_156 {
        (reference - actual).abs() <= 0.000_000_059_604_645
    } else {
        reference.is_sign_negative() == actual.is_sign_negative()
            && reference.to_bits().abs_diff(actual.to_bits()) <= 8192
    }
}

#[test]
fn sun_work_uniform_medium_does_not_recompute_extinction_per_step() {
    let code = crate::shaders::compile_hlsl_source(
        "sun-work:uniform-field",
        &super::world_field_shader_source(),
    )
    .unwrap();
    let mut offset = 1;
    let mut nesting = 0;
    let mut repeated = 0;
    while code[offset] as u16 != 0xffff {
        let token = code[offset];
        let opcode = token as u16;
        if opcode == 0xfffe {
            offset += 1 + ((token >> 16) & 0x7fff) as usize;
            continue;
        }
        match opcode {
            27 | 38 => nesting += 1,
            29 | 39 => nesting -= 1,
            14 if nesting == 1 => repeated += 1,
            _ => {}
        }
        offset += 1 + ((token >> 24) & 0xf) as usize;
    }
    assert_eq!(
        repeated, 0,
        "uniform air repeats its invariant extinction exponential inside each march"
    );
    assert_eq!(nesting, 0);
}

#[test]
fn sun_work_world_field_has_no_projected_fallback_work() {
    let code = crate::shaders::compile_hlsl_source(
        "sun-work:world-only-field",
        &super::world_field_shader_source(),
    )
    .unwrap();
    let (instructions, textures) = sun_work_bytecode_counts(&code);
    assert!(
        textures <= 7,
        "world field includes unrelated projected texture work: {textures}"
    );
    assert!(
        instructions <= 1114,
        "world field instruction work: {instructions}"
    );
}

#[test]
fn sun_work_quarter_depth_uses_four_encoded_packets() {
    let code = crate::shaders::compile_hlsl_source(
        "sun-work:interval-reduction",
        &super::interval_reduction_shader_source(),
    )
    .unwrap();
    let (instructions, textures) = sun_work_bytecode_counts(&code);
    assert_eq!(
        textures, 4,
        "sun field repeated full-resolution depth reads"
    );
    assert!(
        instructions <= 56,
        "sun interval reduction work: {instructions}"
    );
}

#[test]
fn sun_work_reduced_intervals_match_full_depth_gpu_pixels() {
    use super::{
        AtmosphereTargets, bind_pipeline_state, depth_reduce_shader_source, draw_depth_reduce_to,
        draw_interval_reduce_to,
    };
    let owner = raster_device();
    let device = owner.as_ref();
    let half =
        crate::shaders::compile_hlsl_source("sun-work:half-depth", super::DEPTH_REDUCE_SHADER)
            .unwrap();
    let quarter = crate::shaders::compile_hlsl_source(
        "sun-work:quarter-depth",
        &depth_reduce_shader_source(4),
    )
    .unwrap();
    let interval = crate::shaders::compile_hlsl_source(
        "sun-work:interval-depth",
        &super::interval_reduction_shader_source(),
    )
    .unwrap();
    let half = device.create_pixel_shader(&half).unwrap();
    let quarter = device.create_pixel_shader(&quarter).unwrap();
    let interval = device.create_pixel_shader(&interval).unwrap();
    for (width, height) in [(64u32, 64u32), (67, 35), (3, 7), (1, 1)] {
        for reversed in [false, true] {
            for pattern in 0..3 {
                let depth = device
                    .create_texture(width, height, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)
                    .unwrap();
                let pixels: Vec<_> = (0..width * height)
                    .map(|index| {
                        let x = index % width;
                        let y = index / width;
                        let value = match pattern {
                            0 => {
                                if reversed {
                                    0
                                } else {
                                    255
                                }
                            }
                            1 => 8 + (x * 7 + y * 13) % 240,
                            _ => {
                                if x == width / 2 {
                                    220
                                } else if reversed {
                                    0
                                } else {
                                    255
                                }
                            }
                        };
                        0xff00_0000 | (value << 16)
                    })
                    .collect();
                depth.write_level0_argb(width, height, &pixels).unwrap();
                let mut frame = frame(&depth, [0.3, 0.4, 0.866_025_4]);
                frame.depth.world_projection.reversed_depth = Some(reversed);
                let targets = AtmosphereTargets::create(&device, width, height, 2).unwrap();
                let quarter_width = width.div_ceil(4);
                let quarter_height = height.div_ceil(4);
                let reference = device
                    .create_render_target_texture(
                        quarter_width,
                        quarter_height,
                        D3DFMT_A16B16G16R16F,
                    )
                    .unwrap();
                let actual = device
                    .create_render_target_texture(
                        quarter_width,
                        quarter_height,
                        D3DFMT_A16B16G16R16F,
                    )
                    .unwrap();
                let desc = depth.surface_level(0).unwrap().desc().unwrap();
                device.begin_scene().unwrap();
                bind_pipeline_state(&device).unwrap();
                draw_depth_reduce_to(
                    &device,
                    &half,
                    &targets.depth.surface,
                    targets.width,
                    targets.height,
                    &desc,
                    frame,
                    frame.depth.texture.unwrap(),
                )
                .unwrap();
                draw_depth_reduce_to(
                    &device,
                    &quarter,
                    &reference.surface_level(0).unwrap(),
                    quarter_width,
                    quarter_height,
                    &desc,
                    frame,
                    frame.depth.texture.unwrap(),
                )
                .unwrap();
                draw_interval_reduce_to(
                    &device,
                    &interval,
                    &targets,
                    &actual.surface_level(0).unwrap(),
                    quarter_width,
                    quarter_height,
                )
                .unwrap();
                device.end_scene().unwrap();
                let reference = sun_work_readback(&device, &reference);
                let actual = sun_work_readback(&device, &actual);
                assert_eq!(
                    actual, reference,
                    "FP16 interval changed: {width}x{height}, reversed={reversed}, pattern={pattern}"
                );
            }
        }
    }
}

#[test]
fn sun_work_paired_integration_matches_released_gpu_layers() {
    use super::{
        AtmosphereTargets, ShaftTargets, bind_pipeline_state, bind_target, draw_depth_reduce_to,
        draw_integration, draw_quad, integration_shader_source, resolve_contributions,
    };
    let owner = raster_device();
    let device = owner.as_ref();
    assert!(device.simultaneous_render_target_count().unwrap() >= 2);
    let effect =
        AtmosphereEffect::create_from_bytecode(&device, &AtmosphereBytecode::compile().unwrap())
            .unwrap();
    let targets = AtmosphereTargets::create(&device, TEST_SIZE, TEST_SIZE, 2).unwrap();
    let field = ShaftTargets::create(&device, TEST_SIZE / 4, TEST_SIZE / 4).unwrap();
    let field_upload = crate::shaders::compile_hlsl_source(
        "sun-work:field-input",
        b"float4 Main(float2 uv : TEXCOORD0) : COLOR0 { return float4(0.015 + uv.x * 0.01, 0.045 + uv.y * 0.015, 0.1, 1.0); }",
    )
    .unwrap();
    let field_upload = device.create_pixel_shader(&field_upload).unwrap();
    device.begin_scene().unwrap();
    bind_pipeline_state(&device).unwrap();
    bind_target(&device, &field.mask.surface, field.width, field.height).unwrap();
    device.set_pixel_shader(&field_upload).unwrap();
    draw_quad(&device, field.width, field.height).unwrap();
    device.end_scene().unwrap();
    for quality in [
        AtmosphereQuality::Performance,
        AtmosphereQuality::High,
        AtmosphereQuality::Ultra,
    ] {
        let samples = match quality {
            AtmosphereQuality::Performance => 8,
            AtmosphereQuality::High => 12,
            AtmosphereQuality::Ultra => 20,
        };
        let mut reference_source =
            format!("#define ATMOSPHERE_SAMPLE_COUNT {samples}\n").into_bytes();
        reference_source.extend_from_slice(include_bytes!(
            "../../shaders/tests/atmosphere_integrate_sun_work_baseline.hlsl"
        ));
        let reference_code =
            crate::shaders::compile_hlsl_source("sun-work:released-integration", &reference_source)
                .unwrap();
        let reference = device.create_pixel_shader(&reference_code).unwrap();
        let paired_code = crate::shaders::compile_hlsl_source(
            "sun-work:paired-integration",
            &super::paired_integration_shader_source(samples),
        )
        .unwrap();
        let (instructions, textures) = sun_work_bytecode_counts(&paired_code);
        let (maximum_instructions, maximum_textures, maximum_bytes) = match samples {
            8 => (1229, 23, 19072),
            12 => (1446, 31, 22424),
            _ => (1880, 47, 29128),
        };
        assert!(
            instructions <= maximum_instructions
                && textures <= maximum_textures
                && paired_code.len() * 4 <= maximum_bytes,
            "paired shader exceeded its qualified tier budget"
        );
        let reference_instructions = sun_work_bytecode_counts(&reference_code).0;
        assert!(
            instructions < reference_instructions * 2,
            "paired integration exceeded two released passes"
        );
        let paired = device.create_pixel_shader(&paired_code).unwrap();
        for (height_density, noise) in [(0.0, 0.0), (0.000_003, 0.18)] {
            for reversed in [false, true] {
                for mixed in [false, true] {
                    let depth = raw_depth(&device, mixed);
                    let mut frame = frame(&depth, [0.3, 0.4, 0.866_025_4]);
                    frame.depth.world_projection.reversed_depth = Some(reversed);
                    frame.sky.as_mut().unwrap().sun_light = [1.0, 0.9, 0.8];
                    let mut settings = settings(true);
                    settings.quality = quality;
                    settings.fog_enabled = height_density > 0.0;
                    settings.height_density = height_density;
                    settings.noise_amount = noise;
                    let contributions = resolve_contributions(frame, settings);
                    let desc = depth.surface_level(0).unwrap().desc().unwrap();
                    device.begin_scene().unwrap();
                    bind_pipeline_state(&device).unwrap();
                    draw_depth_reduce_to(
                        &device,
                        &effect.depth_reduce_half_shader,
                        &targets.depth.surface,
                        targets.width,
                        targets.height,
                        &desc,
                        frame,
                        frame.depth.texture.unwrap(),
                    )
                    .unwrap();
                    for far in [false, true] {
                        draw_integration(
                            &device,
                            &reference,
                            &targets,
                            &effect.density_noise,
                            &field.mask.texture,
                            None,
                            None,
                            frame,
                            settings,
                            contributions,
                            false,
                            Some(&field),
                            if far {
                                IntegrationPass::Far
                            } else {
                                IntegrationPass::Near
                            },
                        )
                        .unwrap();
                    }
                    device.end_scene().unwrap();
                    let reference_layers = [
                        sun_work_readback(&device, &targets.near_atmosphere.texture),
                        sun_work_readback(&device, &targets.far_atmosphere.texture),
                    ];
                    device.begin_scene().unwrap();
                    bind_pipeline_state(&device).unwrap();
                    clear_target(&device, &targets.near_atmosphere.texture);
                    clear_target(&device, &targets.far_atmosphere.texture);
                    draw_integration(
                        &device,
                        &paired,
                        &targets,
                        &effect.density_noise,
                        &field.mask.texture,
                        None,
                        None,
                        frame,
                        settings,
                        contributions,
                        false,
                        Some(&field),
                        IntegrationPass::Paired,
                    )
                    .unwrap();

                    device.end_scene().unwrap();
                    let actual_layers = [
                        sun_work_readback(&device, &targets.near_atmosphere.texture),
                        sun_work_readback(&device, &targets.far_atmosphere.texture),
                    ];
                    for (expected, actual) in reference_layers.iter().zip(&actual_layers) {
                        for (expected, actual) in expected.iter().zip(actual) {
                            for channel in 0..4 {
                                assert!(actual[channel].is_finite());
                                assert!(
                                    (expected[channel] - actual[channel]).abs()
                                        <= 0.000_061_035_156,
                                    "paired layer mismatch: quality={quality:?}, reversed={reversed}, mixed={mixed}, height={height_density}, noise={noise}, expected={expected:?}, actual={actual:?}"
                                );
                            }
                        }
                    }
                }
            }
        }
        // Keep the sequential production variant under its released limits.
        assert_eq!(
            sun_work_bytecode_counts(
                &crate::shaders::compile_hlsl_source(
                    "sun-work:sequential",
                    &integration_shader_source(samples)
                )
                .unwrap()
            )
            .0,
            reference_instructions
        );
    }
}

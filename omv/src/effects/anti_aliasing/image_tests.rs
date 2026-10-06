//! Execute OMV's full SMAA graph against the official HLSL3 graph on D3D9.
//!
//! Inputs specify the new reference-SMAA feature (diagonals, corners, long
//! edges, borders and unchanged alpha); they do not reconstruct a game scene.
//! The oracle compiles the upstream implementation and renders its own passes.

use super::*;
use libpsycho::os::windows::{directx9::*, winapi::get_desktop_window};

const REFERENCE_EDGES: &[u8] = br"
sampler2D Input : register(s0);
float4 Main(float2 uv:TEXCOORD0):COLOR0 {
    float4 offsets[3]; SMAAEdgeDetectionVS(uv, offsets);
    float2 edges;
    if (Options0.x < 0.5) edges = SMAALumaEdgeDetectionPS(uv, offsets, Input);
    else edges = SMAAColorEdgeDetectionPS(uv, offsets, Input);
    return float4(edges, 0, 0);
}";
const REFERENCE_WEIGHTS: &[u8] = br"
sampler2D Input : register(s0);
sampler2D Area : register(s1);
sampler2D Search : register(s2);
float4 Main(float2 uv:TEXCOORD0):COLOR0 {
    float2 pixel; float4 offsets[3];
    SMAABlendingWeightCalculationVS(uv, pixel, offsets);
    return SMAABlendingWeightCalculationPS(uv, pixel, offsets, Input, Area, Search, 0);
}";
const REFERENCE_BLEND: &[u8] = br"
sampler2D Input : register(s0);
sampler2D Weights : register(s1);
float4 Main(float2 uv:TEXCOORD0):COLOR0 {
    float4 offsets; SMAANeighborhoodBlendingVS(uv, offsets);
    float4 color = SMAANeighborhoodBlendingPS(uv, offsets, Input, Weights);
    color.a = tex2Dlod(Input, float4(uv,0,0)).a;
    return color;
}";

fn shader(device: &Device9Ref<'_>, source: &[u8]) -> PixelShader9 {
    device
        .create_pixel_shader(
            &shaders::compile_hlsl_source_target(
                "smaa-official-oracle",
                &smaa::source(source),
                "ps_3_0",
            )
            .unwrap(),
        )
        .unwrap()
}

fn effect(device: &Device9Ref<'_>) -> AntiAliasingEffect {
    let code = AntiAliasingBytecode::compile().unwrap();
    AntiAliasingEffect {
        fast_fxaa: device.create_pixel_shader(&code.fast_fxaa).unwrap(),
        nfaa: device.create_pixel_shader(&code.nfaa).unwrap(),
        axaa: device.create_pixel_shader(&code.axaa).unwrap(),
        dlaa_prefilter: device.create_pixel_shader(&code.dlaa_prefilter).unwrap(),
        dlaa_resolve: device.create_pixel_shader(&code.dlaa_resolve).unwrap(),
        smaa_edges: device.create_pixel_shader(&code.smaa_edges).unwrap(),
        smaa_weights: device.create_pixel_shader(&code.smaa_weights).unwrap(),
        smaa_blend: device.create_pixel_shader(&code.smaa_blend).unwrap(),
        scratch_primary: None,
        scratch_secondary: None,
    }
}

fn read(device: &Device9Ref<'_>, texture: &Texture9) -> Vec<[f32; 4]> {
    let surface = texture.surface_level(0).unwrap();
    let desc = surface.desc().unwrap();
    let memory = device
        .create_system_memory_surface(desc.Width, desc.Height, desc.Format)
        .unwrap();
    device.copy_render_target_data(&surface, &memory).unwrap();
    memory.read_rgba8().unwrap()
}

fn setup(device: &Device9Ref<'_>) {
    device.set_depth_stencil_surface(None).unwrap();
    for target in 1..device.simultaneous_render_target_count().unwrap().min(4) {
        device.clear_render_target(target).unwrap();
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
    ] {
        device.set_render_state(state, value).unwrap();
    }
    for sampler in 0..3 {
        for (state, value) in [
            (D3DSAMP_ADDRESSU, D3DTADDRESS_CLAMP.0 as u32),
            (D3DSAMP_ADDRESSV, D3DTADDRESS_CLAMP.0 as u32),
            (D3DSAMP_MINFILTER, D3DTEXF_LINEAR.0 as u32),
            (D3DSAMP_MAGFILTER, D3DTEXF_LINEAR.0 as u32),
            (D3DSAMP_MIPFILTER, D3DTEXF_NONE.0 as u32),
            (D3DSAMP_SRGBTEXTURE, 0),
        ] {
            device.set_sampler_state(sampler, state, value).unwrap();
        }
    }
}

#[test]
fn smaa_graph_matches_official_long_diagonal_corner_and_border_patterns() {
    let owner = create_direct3d9()
        .unwrap()
        .create_windowed_device(get_desktop_window().unwrap(), 73, 57, D3DDEVTYPE_HAL)
        .unwrap();
    let device = owner.as_ref();
    setup(&device);
    let mut production = effect(&device);
    let reference = [
        shader(&device, REFERENCE_EDGES),
        shader(&device, REFERENCE_WEIGHTS),
        shader(&device, REFERENCE_BLEND),
    ];
    let lookup = smaa::LookupTextures::create(&device).unwrap();
    let input = device
        .create_texture(73, 57, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)
        .unwrap();
    let output = device
        .create_render_target_texture(73, 57, D3DFMT_A8R8G8B8)
        .unwrap();
    let surface = output.surface_level(0).unwrap();
    let desc = surface.desc().unwrap();
    let edges = EffectTarget::create(&device, &desc).unwrap();
    let weights = EffectTarget::create(&device, &desc).unwrap();
    let expected = EffectTarget::create(&device, &desc).unwrap();
    let mut config = crate::config::EmbeddedEffectsConfig::default();
    config.smaa.enabled = true;
    let mut source = shaders::merge_embedded_sources(&config, Vec::new())
        .into_iter()
        .find(|s| s.embedded_effect_kind() == Some(EmbeddedEffectKind::Smaa))
        .unwrap();
    let mut alpha_error = 0f32;
    for mode in [0., 1.] {
        for corner in [0., 25., 100.] {
            source.option_constants[0][0] = mode;
            source.option_constants[1][0] = corner;
            for pattern in 0..6 {
                let pixels: Vec<u32> = (0..73 * 57)
                    .map(|i| {
                        let x = i % 73;
                        let y = i / 73;
                        let inside = match pattern {
                            0 => false,
                            1 => x > y,
                            2 => 3 * x > y + 37,
                            3 => x > 12 && y > 9 && (x < 43 || y < 36),
                            4 => (x > 35 && x < 38) || y == 0 || x == 72,
                            _ => (x + y) % 11 < 2,
                        };
                        let rgb = if inside { 0x00d04090 } else { 0x00101720 };
                        (((31 + (x * 3 + y * 5) % 200) as u32) << 24) | rgb
                    })
                    .collect();
                input.write_level0_argb(73, 57, &pixels).unwrap();
                device.begin_scene().unwrap();
                setup(&device);
                production
                    .draw(&device, &surface, &desc, &source, &input)
                    .unwrap();
                // The oracle owns its own resource graph; no production target
                // supplies reference edges or weights.
                bind_constants(&device, &desc, &source).unwrap();
                bind_target(&device, &edges.surface, &desc).unwrap();
                device
                    .clear_attachments(D3DCLEAR_TARGET as u32, 0, 1., 0)
                    .unwrap();
                device.set_texture(0, &input).unwrap();
                device.set_pixel_shader(&reference[0]).unwrap();
                draw_quad(&device, &desc).unwrap();
                bind_target(&device, &weights.surface, &desc).unwrap();
                device.set_texture(0, &edges.texture).unwrap();
                device.set_texture(1, &lookup.area).unwrap();
                device.set_texture(2, &lookup.search).unwrap();
                device.set_pixel_shader(&reference[1]).unwrap();
                draw_quad(&device, &desc).unwrap();
                bind_target(&device, &expected.surface, &desc).unwrap();
                device.set_texture(0, &input).unwrap();
                device.set_texture(1, &weights.texture).unwrap();
                device.clear_texture(2).unwrap();
                device.set_pixel_shader(&reference[2]).unwrap();
                draw_quad(&device, &desc).unwrap();
                device.end_scene().unwrap();
                let actual = read(&device, &output);
                let expected = read(&device, &expected.texture);
                let mut maximum = 0f32;
                for (i, (a, b)) in actual.iter().zip(&expected).enumerate() {
                    assert!(a.iter().all(|v| v.is_finite()));
                    alpha_error = alpha_error.max((a[3] - ((pixels[i] >> 24) as f32 / 255.)).abs());
                    for c in 0..3 {
                        maximum = maximum.max((a[c] - b[c]).abs());
                    }
                }
                assert!(
                    maximum <= 1. / 255.,
                    "reference mismatch: mode={mode}, corner={corner}, pattern={pattern}, error={maximum}"
                );
            }
        }
    }
    assert!(alpha_error < 0.5 / 255., "alpha changed by {alpha_error}");
}

/// Debug selection, stale-edge clearing, target resize and effect retirement
/// execute the same shipped graph, including pre-bound target aliases.
#[test]
fn smaa_debug_resize_and_repeated_flat_frames_preserve_alpha() {
    let owner = create_direct3d9()
        .unwrap()
        .create_windowed_device(get_desktop_window().unwrap(), 73, 57, D3DDEVTYPE_HAL)
        .unwrap();
    let device = owner.as_ref();
    let mut production = effect(&device);
    let mut config = crate::config::EmbeddedEffectsConfig::default();
    config.smaa.enabled = true;
    let mut source = shaders::merge_embedded_sources(&config, Vec::new())
        .into_iter()
        .find(|s| s.embedded_effect_kind() == Some(EmbeddedEffectKind::Smaa))
        .unwrap();
    for (width, height) in [(37, 25), (53, 29)] {
        let input = device
            .create_texture(width, height, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)
            .unwrap();
        let output = device
            .create_render_target_texture(width, height, D3DFMT_A8R8G8B8)
            .unwrap();
        let surface = output.surface_level(0).unwrap();
        let desc = surface.desc().unwrap();
        for debug in [1., 2., 0.] {
            source.option_constants[1][1] = debug;
            for patterned in [true, false] {
                let pixels: Vec<u32> = (0..width * height)
                    .map(|i| {
                        0x63000000
                            | if patterned && i % width > i / width {
                                0xd04090
                            } else {
                                0x101720
                            }
                    })
                    .collect();
                input.write_level0_argb(width, height, &pixels).unwrap();
                setup(&device);
                if let Some(target) = production.scratch_primary.as_ref() {
                    device.set_texture(2, &target.texture).unwrap();
                }
                if let Some(owner) = production.scratch_secondary.as_ref() {
                    device
                        .set_texture(1, &owner.resources.target.texture)
                        .unwrap();
                }
                device.begin_scene().unwrap();
                production
                    .draw(&device, &surface, &desc, &source, &input)
                    .unwrap();
                device.end_scene().unwrap();
                let actual = read(&device, &output);
                assert!(
                    actual
                        .iter()
                        .all(|p| (p[3] - 99. / 255.).abs() < 0.5 / 255.)
                );
                let selected = if debug == 1. {
                    read(
                        &device,
                        &production.scratch_primary.as_ref().unwrap().texture,
                    )
                } else if debug == 2. {
                    read(
                        &device,
                        &production
                            .scratch_secondary
                            .as_ref()
                            .unwrap()
                            .resources
                            .target
                            .texture,
                    )
                } else {
                    read(&device, &input)
                };
                if debug > 0. || !patterned {
                    for (actual, selected) in actual.iter().zip(&selected) {
                        for c in 0..3 {
                            assert!((actual[c] - selected[c]).abs() <= 1. / 255.);
                        }
                    }
                }
                if debug == 1. && width == 37 {
                    assert!(production.scratch_secondary.is_none());
                }
                assert_eq!(
                    [
                        production.scratch_primary.as_ref().unwrap().width,
                        production.scratch_primary.as_ref().unwrap().height
                    ],
                    [width, height]
                );
            }
        }
    }
    // The same device can create and draw a new effect after the old owner is
    // retired. Runtime reset/device-release drops this exact resource owner.
    drop(production);
    let fresh = effect(&device);
    assert!(fresh.scratch_primary.is_none() && fresh.scratch_secondary.is_none());
}

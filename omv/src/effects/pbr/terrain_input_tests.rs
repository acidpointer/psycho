//! Executable production terrain input/shader qualification on a HAL device.
//! These parameterized ABI cases qualify input publication and state isolation;
//! they do not claim to reproduce an unrecorded game frame or stale registers.

use super::super::shader_registry::{self, ShaderStage};
use super::*;
use libpsycho::os::windows::{directx9::*, winapi::get_desktop_window};

#[repr(C)]
#[derive(Clone, Copy)]
struct Vertex {
    position: [f32; 4],
    tangent: [f32; 3],
    binormal: [f32; 3],
    normal: [f32; 3],
    uv: [f32; 4],
    color: [f32; 4],
    blend0: [f32; 4],
    blend1: [f32; 4],
}

fn bytecode(stage: ShaderStage, family: Family, companion: bool) -> Vec<u32> {
    let id = match family {
        Family::Lod => shader_registry::land_lod_template_id(stage),
        Family::Fade => shader_registry::terrain_fade_template_id(stage),
        Family::Close { layers, lights } => {
            let sls = if stage == ShaderStage::Vertex {
                2100
            } else {
                2092 + (layers as u16 - 1) * 8
                    + match lights {
                        0 => 0,
                        6 => 2,
                        12 => 4,
                        24 => 6,
                        _ => unreachable!(),
                    }
                    + u16::from(companion)
            };
            shader_registry::close_terrain_template_id(stage, sls).unwrap()
        }
    };
    let template = shader_registry::template_at(id).unwrap();
    crate::shaders::compile_hlsl_source_target(
        "terrain_input_qualification",
        &shader_registry::template_source(id, template),
        if stage == ShaderStage::Vertex {
            "vs_3_0"
        } else {
            "ps_3_0"
        },
    )
    .unwrap()
}

#[test]
fn terrain_input_publication_restores_every_borrowed_constant() {
    let owner = create_direct3d9()
        .unwrap()
        .create_windowed_device(get_desktop_window().unwrap(), 16, 16, D3DDEVTYPE_HAL)
        .unwrap();
    let device = owner.as_ref();
    // Distinct values expose range offsets, cross-stage mistakes, and gaps.
    let prior_pixel: [[f32; 4]; 96] = std::array::from_fn(|i| [i as f32 + 0.25; 4]);
    let prior_vertex: [[f32; 4]; 32] = std::array::from_fn(|i| [i as f32 + 0.5; 4]);
    for family in [
        Family::Lod,
        Family::Fade,
        Family::Close {
            layers: 1,
            lights: 0,
        },
        Family::Close {
            layers: 7,
            lights: 24,
        },
    ] {
        device.set_pixel_shader_constant_f(0, &prior_pixel).unwrap();
        device
            .set_vertex_shader_constant_f(0, &prior_vertex)
            .unwrap();
        let scope = ConstantScope::capture(&device, family).unwrap();
        let inputs = Inputs {
            family,
            pixel: [[0.125; 4]; 60],
            fog: [[1000.0, 500.0, 1.0, 0.0], [0.0; 4]],
        };
        assert!(inputs.upload(&device));
        // Execute the existing production user-control writer inside the same
        // journal, as admission does. It must not escape into the next draw.
        super::super::constants::upload_terrain_constants(
            &device,
            matches!(family, Family::Close { .. })
                .then_some(&terrain_lights::SupplementalTerrainLights::default()),
        )
        .unwrap();
        assert!(scope.restore(&device));
        let mut pixel = [[0.0; 4]; 96];
        let mut vertex = [[0.0; 4]; 32];
        device.pixel_shader_constant_f(0, &mut pixel).unwrap();
        device.vertex_shader_constant_f(0, &mut vertex).unwrap();
        assert_eq!(pixel, prior_pixel);
        assert_eq!(vertex, prior_vertex);
    }
}

#[test]
fn shipped_terrain_families_consume_owned_fog_and_lighting() {
    let owner = create_direct3d9()
        .unwrap()
        .create_windowed_device(get_desktop_window().unwrap(), 16, 16, D3DDEVTYPE_HAL)
        .unwrap();
    let device = owner.as_ref();
    exercise_shaders(&device, || {});
}

/// Render the actual production VS/PS before and after an optional transaction.
/// The callback must preserve the established terrain device state.
pub(crate) fn exercise_shaders(device: &Device9Ref<'_>, mut between: impl FnMut()) {
    let elements = [
        (0, D3DDECLTYPE_FLOAT4, D3DDECLUSAGE_POSITION, 0),
        (16, D3DDECLTYPE_FLOAT3, D3DDECLUSAGE_TANGENT, 0),
        (28, D3DDECLTYPE_FLOAT3, D3DDECLUSAGE_BINORMAL, 0),
        (40, D3DDECLTYPE_FLOAT3, D3DDECLUSAGE_NORMAL, 0),
        (52, D3DDECLTYPE_FLOAT4, D3DDECLUSAGE_TEXCOORD, 0),
        (68, D3DDECLTYPE_FLOAT4, D3DDECLUSAGE_COLOR, 0),
        (84, D3DDECLTYPE_FLOAT4, D3DDECLUSAGE_TEXCOORD, 1),
        (100, D3DDECLTYPE_FLOAT4, D3DDECLUSAGE_TEXCOORD, 2),
    ];
    let mut declaration: Vec<_> = elements
        .into_iter()
        .map(|(offset, ty, usage, index)| D3DVERTEXELEMENT9 {
            Stream: 0,
            Offset: offset,
            Type: ty.0 as u8,
            Method: 0,
            Usage: usage.0 as u8,
            UsageIndex: index,
        })
        .collect();
    declaration.push(D3DVERTEXELEMENT9 {
        Stream: 0xFF,
        Type: D3DDECLTYPE_UNUSED.0 as u8,
        ..Default::default()
    });
    let decl = device.create_vertex_declaration(&declaration).unwrap();
    device.set_vertex_declaration(&decl).unwrap();
    let target = device
        .create_render_target_texture(16, 16, D3DFMT_A16B16G16R16F)
        .unwrap();
    let surface = target.surface_level(0).unwrap();
    let staging = device
        .create_system_memory_surface(16, 16, D3DFMT_A16B16G16R16F)
        .unwrap();
    device.set_depth_stencil_surface(None).unwrap();
    device.set_render_target(0, &surface).unwrap();
    for slot in 1..device.device_caps().unwrap().NumSimultaneousRTs.min(4) {
        device.clear_render_target(slot).unwrap();
    }
    for (state, value) in [
        (D3DRS_ZENABLE, 0),
        (D3DRS_ZWRITEENABLE, 0),
        (D3DRS_ALPHABLENDENABLE, 0),
        (D3DRS_ALPHATESTENABLE, 0),
        (D3DRS_STENCILENABLE, 0),
        (D3DRS_SCISSORTESTENABLE, 0),
        (D3DRS_CULLMODE, D3DCULL_NONE.0 as u32),
        (D3DRS_SRGBWRITEENABLE, 0),
        (D3DRS_COLORWRITEENABLE, 15),
        (D3DRS_MULTISAMPLEMASK, u32::MAX),
        (D3DRS_CLIPPLANEENABLE, 0),
    ] {
        device.set_render_state(state, value).unwrap();
    }
    device
        .set_viewport(&D3DVIEWPORT9 {
            Width: 16,
            Height: 16,
            MaxZ: 1.0,
            ..Default::default()
        })
        .unwrap();
    let albedo = device
        .create_texture(1, 1, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)
        .unwrap();
    albedo.write_level0_argb_pixel(0xFF808080).unwrap();
    let normal = device
        .create_texture(1, 1, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)
        .unwrap();
    normal.write_level0_argb_pixel(0xFF8080FF).unwrap();
    let supplemental = device.create_dynamic_rgba32f_texture(64, 1).unwrap();
    supplemental.write_discard(&[[0.0; 4]; 64]).unwrap();
    for stage in 0..15 {
        for (state, value) in [
            (D3DSAMP_ADDRESSU, D3DTADDRESS_CLAMP.0),
            (D3DSAMP_ADDRESSV, D3DTADDRESS_CLAMP.0),
            (D3DSAMP_MINFILTER, D3DTEXF_POINT.0),
            (D3DSAMP_MAGFILTER, D3DTEXF_POINT.0),
            (D3DSAMP_MIPFILTER, D3DTEXF_NONE.0),
            (D3DSAMP_SRGBTEXTURE, 0),
        ] {
            device
                .set_sampler_state(stage, state, value as u32)
                .unwrap();
        }
    }
    let mut families = vec![(Family::Lod, false), (Family::Fade, false)];
    for layers in [1, 7] {
        for lights in [0, 6, 12, 24] {
            for companion in [false, true] {
                families.push((Family::Close { layers, lights }, companion));
            }
        }
    }
    for (family, companion) in families {
        let vs = device
            .create_vertex_shader(&bytecode(ShaderStage::Vertex, family, companion))
            .unwrap();
        let ps = device
            .create_pixel_shader(&bytecode(ShaderStage::Pixel, family, companion))
            .unwrap();
        device.set_vertex_shader(&vs).unwrap();
        device.set_pixel_shader(&ps).unwrap();
        for stage in 0..14 {
            let is_normal = match family {
                Family::Close { .. } => stage >= 7,
                Family::Lod => stage == 1 || stage == 7,
                Family::Fade => stage == 1,
            };
            device
                .set_texture(stage, if is_normal { &normal } else { &albedo })
                .unwrap();
        }
        device.set_texture(14, supplemental.texture()).unwrap();
        let mut vertex_constants = [[0.0; 4]; 26];
        for i in 0..4 {
            vertex_constants[i][i] = 1.0;
            vertex_constants[8 + i][i] = 1.0;
        }
        vertex_constants[16] = [0.0, 0.0, 10.0, 1.0];
        vertex_constants[19] = [1.0, 0.0, 0.0, 0.0];
        vertex_constants[25] = [0.0, 0.0, 1.0, 1.0];
        device
            .set_vertex_shader_constant_f(0, &vertex_constants)
            .unwrap();
        let mut pixel_constants = [[0.0; 4]; 96];
        pixel_constants[1] = [0.5; 4];
        pixel_constants[18] = [0.0, 0.0, 1.0, 1.0];
        pixel_constants[89] = [0.0, 1.0, 1.0, 1.0];
        pixel_constants[90] = [1.0, 0.0, 0.0, 1.75];
        device
            .set_pixel_shader_constant_f(0, &pixel_constants)
            .unwrap();
        let triangle = [
            [-1.0, -1.0, 0.5, 1.0],
            [3.0, -1.0, 0.5, 1.0],
            [-1.0, 3.0, 0.5, 1.0],
        ]
        .map(|position| Vertex {
            position,
            tangent: [1.0, 0.0, 0.0],
            binormal: [0.0, 1.0, 0.0],
            normal: [0.0, 0.0, 1.0],
            uv: [0.5; 4],
            color: [1.0; 4],
            blend0: [1.0, 0.0, 0.0, 0.0],
            blend1: [0.0; 4],
        });
        let mut unlit_center = None;
        for lit in [false, true] {
            // Near black fog must leave ambient-lit terrain visible. Fully applied
            // black and colored fog have exact endpoint oracles for every family.
            for (fog, expected) in [
                ([[1000.0, 500.0, 1.0, 0.0], [0.0; 4]], None),
                ([[0.0, 1.0, 1.0, 0.0], [0.0; 4]], Some([0.0; 3])),
                (
                    [[0.0, 1.0, 1.0, 0.0], [0.25, 0.5, 0.75, 0.0]],
                    Some([0.25, 0.5, 0.75]),
                ),
            ] {
                let scope = ConstantScope::capture(device, family).unwrap();
                let mut inputs = Inputs {
                    family,
                    pixel: [[0.0; 4]; 60],
                    fog,
                };
                inputs.pixel[4..6].copy_from_slice(&fog);
                if lit {
                    inputs.pixel[..2].fill([30.0; 4]);
                    inputs.pixel[6] = [30.0; 4];
                }
                let mut has_point = false;
                if let Family::Close { lights, .. } = family {
                    if lit && lights != 0 {
                        inputs.pixel[56][0] = lights as f32;
                        inputs.pixel[31..31 + lights].fill([0.0, 0.0, 2.0, 10.0]);
                        // Only the final slot emits light: each capacity boundary
                        // must actually be consumed, not just compile successfully.
                        inputs.pixel[7 + lights - 1] = [0.25, 0.25, 0.25, 1.0];
                        has_point = true;
                    }
                    let supplement_count = usize::from(lit && companion && lights < 24);
                    let mut texels = [[0.0; 4]; 64];
                    texels[0] = [0.0, 0.0, 2.0, 10.0];
                    texels[1] = [0.25, 0.25, 0.25, 1.0];
                    supplemental.write_discard(&texels).unwrap();
                    device
                        .set_pixel_shader_constant_f(
                            91,
                            &[[supplement_count as f32, 0.0, 0.0, 0.0]],
                        )
                        .unwrap();
                    has_point |= supplement_count != 0;
                } else {
                    device
                        .set_pixel_shader_constant_f(3, &[[if lit { 0.25 } else { 0.0 }; 4]])
                        .unwrap();
                }
                assert!(inputs.upload(device));
                let mut before = None;
                for phase in 0..2 {
                    device
                        .clear_attachments(D3DCLEAR_TARGET as u32, 0xFFFF00FF, 1.0, 0)
                        .unwrap();
                    device.begin_scene().unwrap();
                    if phase == 1 {
                        between();
                    }
                    unsafe { device.draw_primitive_up(D3DPT_TRIANGLELIST, 1, &triangle) }.unwrap();
                    device.end_scene().unwrap();
                    device.copy_render_target_data(&surface, &staging).unwrap();
                    let pixels = staging.read_rgba16f().unwrap();
                    for pixel in &pixels {
                        assert!(pixel.iter().all(|x| x.is_finite()), "{family:?}: {pixel:?}");
                        if let Some(expected) = expected {
                            for i in 0..3 {
                                assert!(
                                    (pixel[i] - expected[i]).abs() < 0.002,
                                    "{family:?}: {pixel:?}, expected {expected:?}"
                                );
                            }
                        } else {
                            assert!(
                                pixel[..3].iter().all(|x| *x > 0.05),
                                "{family:?}: near terrain lost ambient lighting: {pixel:?}"
                            );
                        }
                    }
                    if expected.is_none() && phase == 0 {
                        let center = pixels[8 * 16 + 8][0];
                        if !lit {
                            unlit_center = Some(center);
                        } else if has_point {
                            assert!(
                                center > unlit_center.unwrap() + 0.005,
                                "last native/supplemental slot did not illuminate {family:?}: {center}"
                            );
                        }
                    }
                    if let Some(before) = &before {
                        assert_eq!(&pixels, before, "transaction changed {family:?}");
                    }
                    before = Some(pixels);
                }
                assert!(scope.restore(device));
            }
        }
    }
}

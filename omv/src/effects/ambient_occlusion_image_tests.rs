//! Approved AO design regressions through production D3D9 extraction.
//!
//! Authored depth steps exercise overlap, ambient floors and both depth modes;
//! they do not reconstruct the owner's gameplay captures. The readback shader
//! only expands the production G16R16F result into readable FP16 RGBA.

use super::*;
use crate::{backend::DepthProvider, config::EmbeddedEffectsConfig, shaders::EmbeddedEffectKind};
use libpsycho::os::windows::{directx9::*, winapi::get_desktop_window};

#[test]
fn overlapping_ao_preserves_each_ambient_floor_without_double_darkening() {
    let owner = create_direct3d9()
        .unwrap()
        .create_windowed_device(get_desktop_window().unwrap(), 128, 96, D3DDEVTYPE_HAL)
        .unwrap();
    let device = owner.as_ref();
    let code = AmbientOcclusionBytecode::compile().unwrap();
    let effect = AmbientOcclusionEffect {
        fast_extract_shader: device.create_pixel_shader(&code.fast_extract).unwrap(),
        contact_extract_shader: device.create_pixel_shader(&code.contact_extract).unwrap(),
        combined_extract_shader: device.create_pixel_shader(&code.combined_extract).unwrap(),
        blur_shader: device.create_pixel_shader(&code.blur).unwrap(),
        temporal_shader: device.create_pixel_shader(&code.temporal).unwrap(),
        compose_shader: device.create_pixel_shader(&code.compose).unwrap(),
        targets: None,
        previous_camera: None,
    };
    let targets = AmbientOcclusionTargets::create(&device, 64, 48, D3DFMT_A16B16G16R16F).unwrap();
    assert_eq!(targets.format, D3DFMT_G16R16F);
    let depth = device
        .create_render_target_texture(128, 96, D3DFMT_R32F)
        .unwrap();
    let depth_surface = depth.surface_level(0).unwrap();
    let desc = depth_surface.desc().unwrap();
    let output = device
        .create_render_target_texture(64, 48, D3DFMT_A16B16G16R16F)
        .unwrap();
    let surface = output.surface_level(0).unwrap();
    let memory = device
        .create_system_memory_surface(64, 48, D3DFMT_A16B16G16R16F)
        .unwrap();
    // Test-owned input generation encodes explicitly authored distances using
    // the D3D projection contract (near=5, far=100000), in both depth modes.
    let fill = device
        .create_pixel_shader(
            &shaders::compile_hlsl_source(
                "AO authored depth",
                br#"
        float4 Mode : register(c0);
        float4 Main(float2 uv : TEXCOORD0) : COLOR0 {
            float z = uv.x < 0.5 ? 98.0 : 100.0;
            float d = (100000.0 - 500000.0 / z) / 99995.0;
            return float4(Mode.x > 0.5 ? 1.0 - d : d, 0, 0, 1);
        }
    "#,
            )
            .unwrap(),
        )
        .unwrap();
    let copy = device
        .create_pixel_shader(
            &shaders::compile_hlsl_source(
                "AO readback",
                br#"
        sampler2D Input : register(s0);
        float4 Main(float2 uv : TEXCOORD0) : COLOR0 {
            return float4(tex2Dlod(Input, float4(uv, 0, 0)).rg, 0, 1);
        }
    "#,
            )
            .unwrap(),
        )
        .unwrap();
    let mut config = EmbeddedEffectsConfig::default();
    config.fast_ao.strength = 3.0;
    config.fast_ao.min_ambient = 0.4;
    config.fast_ao.radius_scale = 400.0;
    config.fast_ao.max_radius_pixels = 16.0;
    config.fast_ao.range_scale = 0.1;
    config.contact_ao.strength = 3.0;
    config.contact_ao.min_ambient = 0.67;
    config.contact_ao.radius_pixels = 10.0;
    config.contact_ao.range_scale = 0.1;
    let sources = shaders::merge_embedded_sources(&config, Vec::new());
    let fast = sources
        .iter()
        .find(|s| s.embedded_effect_kind() == Some(EmbeddedEffectKind::FastAmbientOcclusion))
        .unwrap();
    let contact = sources
        .iter()
        .find(|s| s.embedded_effect_kind() == Some(EmbeddedEffectKind::ContactAmbientOcclusion))
        .unwrap();
    let mut frame = FrameInputs::default();
    frame.camera.available = true;
    frame.camera.near_z = 5.0;
    frame.camera.far_z = 100000.0;
    frame.camera.aspect_ratio = 128.0 / 96.0;
    frame.camera.frustum_left = -1.0;
    frame.camera.frustum_right = 1.0;
    frame.camera.frustum_bottom = -0.75;
    frame.camera.frustum_top = 0.75;
    frame.depth.provider = DepthProvider::FalloutNewVegas;
    frame.depth.texture = DepthTexture::new(depth.as_raw_base_texture());
    frame.depth.world_projection.camera = frame.camera;
    frame.depth.world_projection.sampled_depth_bits = 24;
    for reversed in [false, true] {
        frame.depth.world_projection.reversed_depth = Some(reversed);
        device.begin_scene().unwrap();
        bind_pipeline_state(&device).unwrap();
        bind_target(&device, &depth_surface, 128, 96).unwrap();
        device
            .set_pixel_shader_constant_f(0, &[[reversed as u8 as f32, 0.0, 0.0, 0.0]])
            .unwrap();
        device.set_pixel_shader(&fill).unwrap();
        draw_quad(&device, 128, 96).unwrap();
        device.end_scene().unwrap();
        let mut images = Vec::new();
        for family in [
            AmbientOcclusionFamily::Fast,
            AmbientOcclusionFamily::Contact,
            AmbientOcclusionFamily::Combined,
        ] {
            device.begin_scene().unwrap();
            bind_pipeline_state(&device).unwrap();
            bind_depth_inputs(&device, &frame.depth.texture, &None).unwrap();
            effect
                .draw_extract(
                    &device,
                    &targets,
                    &desc,
                    &frame,
                    (family != AmbientOcclusionFamily::Contact).then_some(fast),
                    (family != AmbientOcclusionFamily::Fast).then_some(contact),
                    family,
                    0,
                )
                .unwrap();
            bind_target(&device, &surface, 64, 48).unwrap();
            device.set_texture(0, &targets.occlusion.texture).unwrap();
            device.set_pixel_shader(&copy).unwrap();
            draw_quad(&device, 64, 48).unwrap();
            device.end_scene().unwrap();
            device.copy_render_target_data(&surface, &memory).unwrap();
            images.push(memory.read_rgba16f().unwrap());
        }
        assert!(
            images[0]
                .iter()
                .zip(&images[1])
                .any(|(a, b)| a[0] > 0.01 && b[0] > 0.01),
            "input must exercise overlapping kernels"
        );
        for (i, ((fast, contact), combined)) in
            images[0].iter().zip(&images[1]).zip(&images[2]).enumerate()
        {
            assert!(
                fast[0] <= 0.6005 && contact[0] <= 0.3305,
                "ambient floor exceeded at {i}: {fast:?} / {contact:?}"
            );
            assert!(
                (combined[0] - fast[0].max(contact[0])).abs() < 0.001,
                "double occlusion at {i}: {fast:?} / {contact:?} / {combined:?}"
            );
            assert_eq!(combined[1], fast[1], "depth key changed");
            assert!(combined.iter().all(|v| v.is_finite()));
        }
    }
}

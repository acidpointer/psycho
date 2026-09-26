//! Offline execution of phase admission and its actual D3D color-copy budget.
//! Uses shipped sources, compilation, scheduling and drawing on a HAL device.
//! No native game objects or substitute effect implementations are involved.

use super::*;
use libpsycho::os::windows::{directx9::*, winapi::get_desktop_window};

// These executions share production phase-work counters/publication.
static RUNTIME_EXECUTION: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct RestoreMenu(bool);

impl Drop for RestoreMenu {
    fn drop(&mut self) {
        MENU_OPEN.store(self.0, Ordering::Release);
    }
}

/// Present must still draw the actual configuration UI when optional scene
/// metadata is unavailable. An offline device has no native renderer singleton;
/// this exercises the real failure boundary without inventing engine objects.
#[test]
fn disabled_depth_keeps_menu_visible_when_scene_metadata_is_unavailable() {
    let _execution = RUNTIME_EXECUTION
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let window = get_desktop_window().unwrap();
    let owner = create_direct3d9()
        .unwrap()
        .create_windowed_device(window, 1920, 1200, D3DDEVTYPE_HAL)
        .unwrap();
    let device = owner.as_ref();
    let target = device.back_buffer(0, 0).unwrap();
    let desc = target.desc().unwrap();
    let readback = device
        .create_system_memory_surface(desc.Width, desc.Height, desc.Format)
        .unwrap();
    let mut runtime = ScreenShaderRuntime::default();
    runtime.device_ptr = device.as_raw() as usize;
    runtime.imgui_hwnd = window as usize;
    // SAFETY: the window and device outlive this context; all calls stay on
    // this test's device thread, serialized with the other runtime executions.
    runtime.imgui =
        Some(unsafe { psycho_imgui::Dx9Context::new(window, device.as_raw()).unwrap() });
    runtime.settings.menu_config.native_pbr.enabled = false;
    runtime
        .settings
        .menu_config
        .embedded_effects
        .depth_of_field
        .enabled = false;
    runtime
        .settings
        .menu_config
        .embedded_effects
        .motion_blur
        .enabled = false;
    runtime.sources = shaders::merge_embedded_sources(
        &crate::config::EmbeddedEffectsConfig::default(),
        Vec::new(),
    )
    .into_iter()
    .filter(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade))
    .collect();
    runtime.sources[0].enabled = true;
    let _menu = RestoreMenu(MENU_OPEN.swap(true, Ordering::AcqRel));
    for provider in [DepthProvider::FalloutNewVegas, DepthProvider::None] {
        runtime.settings.depth_provider = provider;
        for _ in 0..2 {
            device
                .clear_attachments(D3DCLEAR_TARGET as u32, 0xFF000000, 1.0, 0)
                .unwrap();
            device.begin_scene().unwrap();
            // SAFETY: the live device/window remain owned above. Only native
            // scene metadata is unavailable; the production accessor checks it.
            let result = unsafe { runtime.apply_present_frame(device.as_raw(), window, false) };
            device.end_scene().unwrap();
            assert_eq!(result.is_err(), provider == DepthProvider::None);
        }
        device.copy_render_target_data(&target, &readback).unwrap();
        assert!(
            readback
                .read_rgba8()
                .unwrap()
                .iter()
                .any(|pixel| pixel[..3].iter().any(|v| *v > 0.0)),
            "configuration menu disappeared for {provider:?}"
        );
    }
}

/// ImGui consumes the current RT0; Present must explicitly select the
/// swapchain even when an offscreen effect target remains bound on entry.
#[test]
fn present_menu_draws_to_swapchain_and_restores_offscreen_attachments() {
    let _execution = RUNTIME_EXECUTION
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let window = get_desktop_window().unwrap();
    let owner = create_direct3d9()
        .unwrap()
        .create_windowed_device(window, 1920, 1200, D3DDEVTYPE_HAL)
        .unwrap();
    let device = owner.as_ref();
    let target = device.back_buffer(0, 0).unwrap();
    let desc = target.desc().unwrap();
    device
        .clear_attachments(D3DCLEAR_TARGET as u32, 0xFF000000, 1.0, 0)
        .unwrap();
    let scratch = device
        .create_render_target_texture(1920, 1080, desc.Format)
        .unwrap();
    let scratch_surface = scratch.surface_level(0).unwrap();
    device.set_depth_stencil_surface(None).unwrap();
    device.set_render_target(0, &scratch_surface).unwrap();
    let mut runtime = ScreenShaderRuntime::default();
    runtime.device_ptr = device.as_raw() as usize;
    runtime.imgui_hwnd = window as usize;
    // SAFETY: live window/device owners above outlive the context; this
    // serialized test retains all D3D and ImGui calls on their owning thread.
    runtime.imgui =
        Some(unsafe { psycho_imgui::Dx9Context::new(window, device.as_raw()).unwrap() });
    runtime.settings.menu_config.screen_space_shaders = false;
    runtime.settings.depth_provider = DepthProvider::None;
    let _menu = RestoreMenu(MENU_OPEN.swap(true, Ordering::AcqRel));
    for _ in 0..2 {
        device.begin_scene().unwrap();
        // SAFETY: the device and HWND are live for this Present call.
        let result = unsafe { runtime.apply_present_frame(device.as_raw(), window, false) };
        device.end_scene().unwrap();
        result.unwrap();
    }
    assert_eq!(
        device.render_target(0).unwrap().as_raw(),
        scratch_surface.as_raw()
    );
    let viewport = device.viewport().unwrap();
    assert_eq!((viewport.Width, viewport.Height), (1920, 1080));
    let readback = device
        .create_system_memory_surface(desc.Width, desc.Height, desc.Format)
        .unwrap();
    device.copy_render_target_data(&target, &readback).unwrap();
    assert!(
        readback
            .read_rgba8()
            .unwrap()
            .iter()
            .any(|pixel| pixel[..3].iter().any(|v| *v > 0.0)),
        "menu rendered into an offscreen effect target instead of the swapchain"
    );
}

/// Run the shipped sunshaft phase at the reported image/allocation extents.
/// The native viewport is the phase's image boundary; outside pixels belong
/// to native presentation and must survive the complete graph unchanged.
#[test]
fn sunshaft_phase_preserves_native_letterbox_pixels() {
    let _execution = RUNTIME_EXECUTION
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let owner = create_direct3d9()
        .unwrap()
        .create_windowed_device(get_desktop_window().unwrap(), 1920, 1200, D3DDEVTYPE_HAL)
        .unwrap();
    let device = owner.as_ref();
    let target = device.render_target(0).unwrap();
    let desc = target.desc().unwrap();
    let depth = device
        .create_render_target_texture(1920, 1080, D3DFMT_R32F)
        .unwrap();
    device.set_depth_stencil_surface(None).unwrap();
    device
        .set_render_target(0, &depth.surface_level(0).unwrap())
        .unwrap();
    device
        .clear_attachments(D3DCLEAR_TARGET as u32, 0, 1.0, 0)
        .unwrap();
    device
        .clear_attachment_rect(
            &RECT {
                left: 880,
                top: 400,
                right: 1040,
                bottom: 680,
            },
            D3DCLEAR_TARGET as u32,
            0xFF808080,
            1.0,
            0,
        )
        .unwrap();
    device.set_render_target(0, &target).unwrap();
    device
        .clear_attachments(D3DCLEAR_TARGET as u32, 0, 1.0, 0)
        .unwrap();
    let camera = backend::CameraFrame {
        near_z: 5.0,
        far_z: 353840.0,
        aspect_ratio: 16.0 / 9.0,
        frustum_left: -1.3333334,
        frustum_right: 1.3333334,
        frustum_bottom: -0.75,
        frustum_top: 0.75,
        world_transform: backend::CameraTransformFrame {
            available: true,
            ..Default::default()
        },
        available: true,
    };
    let frame = backend::FrameInputs {
        camera,
        depth: DepthFrame::from_textures(
            DepthProvider::FalloutNewVegas,
            backend::DepthTexture::new(depth.as_raw_base_texture()),
            None,
            backend::DepthProjectionFrame {
                camera,
                reversed_depth: Some(true),
                ..Default::default()
            },
            Default::default(),
            23,
        ),
        sky: Some(backend::NativeSkyFrame {
            sky_upper: [0.2, 0.3, 0.6],
            sky_lower: [0.4, 0.45, 0.55],
            horizon: [0.65, 0.6, 0.5],
            sun_light: [1.0; 3],
            sun_disk: [1.0; 3],
            sun_direction: [1.0, 0.0, 0.0],
            daylight: 1.0,
            game_hour: 12.0,
            is_exterior: true,
            reversed_depth: true,
        }),
        material_state: backend::MaterialStateFrame {
            exterior_known: true,
            is_exterior: true,
        },
        ..Default::default()
    };
    sunshafts::service_preparation();
    let deadline = Instant::now() + std::time::Duration::from_secs(30);
    while !sunshafts::preparation_ready() && Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(sunshafts::preparation_ready());
    let mut runtime = ScreenShaderRuntime::default();
    runtime.settings.depth_provider = DepthProvider::FalloutNewVegas;
    runtime.sources = shaders::merge_embedded_sources(
        &crate::config::EmbeddedEffectsConfig::default(),
        Vec::new(),
    )
    .into_iter()
    .filter(|s| s.embedded_effect_kind() == Some(EmbeddedEffectKind::Sunshafts))
    .collect();
    runtime.sources[0].enabled = true;
    let phase = runtime.sources[0].phase;
    runtime.ensure_shaders(&device);
    runtime
        .ensure_phase_color_copy(&device, &desc, phase)
        .unwrap();
    device
        .set_viewport(&D3DVIEWPORT9 {
            X: 0,
            Y: 60,
            Width: 1920,
            Height: 1080,
            MinZ: 0.0,
            MaxZ: 1.0,
        })
        .unwrap();
    device.begin_scene().unwrap();
    runtime
        .draw_passes(&device, &target, &desc, phase, &frame)
        .unwrap();
    device.end_scene().unwrap();
    let readback = device
        .create_system_memory_surface(1920, 1200, desc.Format)
        .unwrap();
    device.copy_render_target_data(&target, &readback).unwrap();
    let pixels = readback.read_rgba8().unwrap();
    assert!(
        pixels[60 * 1920..1140 * 1920].iter().any(|p| p[0] > 0.03),
        "sunshafts must execute"
    );
    assert!(
        pixels[..60 * 1920]
            .iter()
            .chain(&pixels[1140 * 1920..])
            .all(|p| p[..3] == [0.0; 3]),
        "sunshaft phase modified native letterbox pixels"
    );

    // The same production graph on the actual image-sized target is the
    // reference for sampling, radial filtering and composition. Compare the
    // entire active image, not just black-bar exclusion or shader compilation.
    let image_target = device
        .create_render_target_texture(1920, 1080, desc.Format)
        .unwrap();
    let image_surface = image_target.surface_level(0).unwrap();
    device.set_render_target(0, &image_surface).unwrap();
    device
        .clear_attachments(D3DCLEAR_TARGET as u32, 0, 1.0, 0)
        .unwrap();
    device.begin_scene().unwrap();
    runtime
        .draw_passes(
            &device,
            &image_surface,
            &image_surface.desc().unwrap(),
            phase,
            &frame,
        )
        .unwrap();
    device.end_scene().unwrap();
    let image_readback = device
        .create_system_memory_surface(1920, 1080, desc.Format)
        .unwrap();
    device
        .copy_render_target_data(&image_surface, &image_readback)
        .unwrap();
    let expected = image_readback.read_rgba8().unwrap();
    // Native backbuffer and texture rendering need not round the floating
    // shader result identically at an 8-bit conversion boundary. Permit one
    // destination code step; outside-image pixels above remain bit-exact.
    let mismatch = pixels[60 * 1920..1140 * 1920]
        .iter()
        .zip(&expected)
        .enumerate()
        .find(|(_, (actual, expected))| {
            actual
                .iter()
                .zip(expected.iter())
                .any(|(a, b)| (a - b).abs() > 1.0 / 255.0 + f32::EPSILON)
        });
    assert!(mismatch.is_none(), "letterbox image mismatch: {mismatch:?}");
}

#[test]
fn empty_screen_graph_does_not_request_depth_captures() {
    let _execution = RUNTIME_EXECUTION
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    // Backing readiness is provider-owned. Per-frame capture demand still
    // follows the actual source publication used by the scene hooks.
    let previous = FNV_SCENE_REQUIREMENTS.load(Ordering::Acquire);
    struct RestorePublication(u32);
    impl Drop for RestorePublication {
        fn drop(&mut self) {
            FNV_SCENE_REQUIREMENTS.store(self.0, Ordering::Release);
        }
    }
    let _restore = RestorePublication(previous);
    let mut runtime = ScreenShaderRuntime::default();
    runtime.settings.menu_config.screen_space_shaders = true;
    runtime.settings.depth_provider = DepthProvider::FalloutNewVegas;
    runtime.sources = shaders::merge_embedded_sources(
        &crate::config::EmbeddedEffectsConfig::default(),
        Vec::new(),
    );
    for source in &mut runtime.sources {
        source.enabled = false;
    }
    runtime.publish_fnv_scene_requirements();
    for slot in [
        backend::DepthResolveSlot::World,
        backend::DepthResolveSlot::FirstPerson,
    ] {
        assert!(!needs_fnv_depth_capture(slot));
    }
    runtime
        .sources
        .iter_mut()
        .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade))
        .unwrap()
        .enabled = true;
    runtime.publish_fnv_scene_requirements();
    assert!(!needs_fnv_depth_capture(backend::DepthResolveSlot::World));
    runtime
        .sources
        .iter_mut()
        .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::DepthOfField))
        .unwrap()
        .enabled = true;
    runtime.publish_fnv_scene_requirements();
    assert!(needs_fnv_depth_capture(backend::DepthResolveSlot::World));
    runtime.settings.menu_config.screen_space_shaders = false;
    runtime.publish_fnv_scene_requirements();
    assert!(!needs_fnv_depth_capture(backend::DepthResolveSlot::World));
}

#[test]
fn inactive_final_color_sub_effects_submit_no_color_copy() {
    let _execution = RUNTIME_EXECUTION
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let owner = create_direct3d9()
        .unwrap()
        .create_windowed_device(get_desktop_window().unwrap(), 32, 24, D3DDEVTYPE_HAL)
        .unwrap();
    let device = owner.as_ref();
    let target = device.render_target(0).unwrap();
    let desc = target.desc().unwrap();
    let mut config = crate::config::EmbeddedEffectsConfig::default();
    config.color_grade.enabled = true;
    config.color_grade.color_grading_enabled = false;
    config.color_grade.lut_enabled = false;
    config.color_grade.deband_enabled = false;
    config.color_grade.film_grain_enabled = false;
    config.color_grade.vignette_enabled = false;
    config.color_grade.halation_enabled = false;
    config.color_grade.chromatic_aberration_enabled = false;
    let mut runtime = ScreenShaderRuntime::default();
    runtime.sources = shaders::merge_embedded_sources(&config, Vec::new())
        .into_iter()
        .filter(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade))
        .collect();
    runtime.final_color_shaders = Some(Arc::new(
        blooming_hdr::FinalColorShaderBytecode::prepare().unwrap(),
    ));
    runtime.ensure_shaders(&device);
    let frame = backend::FrameInputs::default();
    let phase = ShaderPhase::FinalImageSpace;
    let before = PHASE_INITIAL_COLOR_COPIES.load(Ordering::Relaxed);
    device.begin_scene().unwrap();
    if runtime.phase_has_applicable_work(phase, &desc, &frame) {
        runtime
            .ensure_phase_color_copy(&device, &desc, phase)
            .unwrap();
        runtime
            .draw_passes(&device, &target, &desc, phase, &frame)
            .unwrap();
    } else {
        runtime.maintain_rejected_phase_state(phase, &frame);
    }
    device.end_scene().unwrap();
    assert_eq!(
        PHASE_INITIAL_COLOR_COPIES.load(Ordering::Relaxed) - before,
        0
    );
    assert!(runtime.final_color_copy.is_none());
    assert!(runtime.blooming_hdr.is_none());

    // A LUT-only selection with no loaded asset has the same zero-work
    // contract as disabled sub-effects. Resolve availability at admission.
    config.color_grade.lut_enabled = true;
    runtime.sources = shaders::merge_embedded_sources(&config, Vec::new())
        .into_iter()
        .filter(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade))
        .collect();
    runtime.invalidate_compiled_shaders();
    runtime.ensure_shaders(&device);
    assert!(!runtime.phase_has_applicable_work(phase, &desc, &frame));

    // An independent finishing effect must still submit its real shader.
    // Uniform input makes its expected output independent of sample offsets.
    config.color_grade.lut_enabled = false;
    config.color_grade.chromatic_aberration_enabled = true;
    runtime.sources = shaders::merge_embedded_sources(&config, Vec::new())
        .into_iter()
        .filter(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade))
        .collect();
    runtime.invalidate_compiled_shaders();
    runtime.ensure_shaders(&device);
    assert!(runtime.phase_has_applicable_work(phase, &desc, &frame));
    runtime.render_target_slots(&device).unwrap();
    runtime
        .ensure_phase_color_copy(&device, &desc, phase)
        .unwrap();
    device
        .clear_attachments(D3DCLEAR_TARGET as u32, 0xFF808080, 1.0, 0)
        .unwrap();
    device.begin_scene().unwrap();
    runtime
        .draw_passes(&device, &target, &desc, phase, &frame)
        .unwrap();
    device.end_scene().unwrap();
    assert_eq!(
        PHASE_INITIAL_COLOR_COPIES.load(Ordering::Relaxed) - before,
        1
    );
    let readback = device
        .create_system_memory_surface(32, 24, desc.Format)
        .unwrap();
    device.copy_render_target_data(&target, &readback).unwrap();
    for pixel in readback.read_rgba8().unwrap() {
        for value in &pixel[..3] {
            assert!((*value - 128.0 / 255.0).abs() <= 1.0 / 255.0);
        }
    }

    // Disabling the last screen effect must retire its actual GPU owners,
    // even when the master switch remains on. Re-enabling must recreate them
    // through the same drawing path rather than retain a disabled history.
    for source in &mut runtime.sources {
        source.enabled = false;
    }
    runtime.rebuild_execution_plan();
    assert!(runtime.final_color_copy.is_none());
    assert!(runtime.final_color_scratch.is_none());
    assert!(runtime.blooming_hdr.is_none());
    for source in &mut runtime.sources {
        source.enabled = true;
    }
    runtime.rebuild_execution_plan();
    runtime
        .ensure_phase_color_copy(&device, &desc, phase)
        .unwrap();
    device.begin_scene().unwrap();
    runtime
        .draw_passes(&device, &target, &desc, phase, &frame)
        .unwrap();
    device.end_scene().unwrap();
    device.copy_render_target_data(&target, &readback).unwrap();
    for pixel in readback.read_rgba8().unwrap() {
        for value in &pixel[..3] {
            assert!((*value - 128.0 / 255.0).abs() <= 1.0 / 255.0);
        }
    }
}

/// A dynamically rejected tail stage must not force the bounded fallback copy.
///
/// Scene admission predicts the per-frame drawing-stage count from the same
/// per-effect contracts the draw re-evaluates. With color-grade work drawing
/// and spatial AA planned but not prepared, the grade stage is the only
/// drawing stage and must target the engine surface directly: exactly one
/// phase color copy, no fallback commit, and the grade result on the target.
#[test]
fn rejected_tail_stage_leaves_the_last_drawing_stage_on_the_engine_surface() {
    let _execution = RUNTIME_EXECUTION
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let owner = create_direct3d9()
        .unwrap()
        .create_windowed_device(get_desktop_window().unwrap(), 32, 24, D3DDEVTYPE_HAL)
        .unwrap();
    let device = owner.as_ref();
    let target = device.render_target(0).unwrap();
    let desc = target.desc().unwrap();
    let mut config = crate::config::EmbeddedEffectsConfig::default();
    config.color_grade.enabled = true;
    config.color_grade.color_grading_enabled = false;
    config.color_grade.lut_enabled = false;
    config.color_grade.deband_enabled = false;
    config.color_grade.film_grain_enabled = false;
    config.color_grade.vignette_enabled = false;
    config.color_grade.halation_enabled = false;
    config.color_grade.chromatic_aberration_enabled = true;
    config.fast_fxaa.enabled = true;
    let mut runtime = ScreenShaderRuntime::default();
    runtime.sources = shaders::merge_embedded_sources(&config, Vec::new())
        .into_iter()
        .filter(|source| {
            matches!(
                source.embedded_effect_kind(),
                Some(EmbeddedEffectKind::ColorGrade) | Some(EmbeddedEffectKind::FastFxaa)
            )
        })
        .collect();
    for source in &mut runtime.sources {
        source.enabled = true;
    }
    runtime.final_color_shaders = Some(Arc::new(
        blooming_hdr::FinalColorShaderBytecode::prepare().unwrap(),
    ));
    runtime.ensure_shaders(&device);
    // The planned spatial-AA stage rejects because its process preparation is
    // inactive in this binary. If that ever changes, this assertion fails
    // loudly instead of silently weakening the rejected-tail coverage.
    assert!(!anti_aliasing::preparation_ready());
    let frame = backend::FrameInputs::default();
    let phase = ShaderPhase::FinalImageSpace;
    let initial_before = PHASE_INITIAL_COLOR_COPIES.load(Ordering::Relaxed);
    let fallback_before = PHASE_FALLBACK_COLOR_COMMITS.load(Ordering::Relaxed);
    device
        .clear_attachments(D3DCLEAR_TARGET as u32, 0xFF808080, 1.0, 0)
        .unwrap();
    device.begin_scene().unwrap();
    assert!(runtime.phase_has_applicable_work(phase, &desc, &frame));
    runtime.render_target_slots(&device).unwrap();
    runtime
        .ensure_phase_color_copy(&device, &desc, phase)
        .unwrap();
    runtime
        .draw_passes(&device, &target, &desc, phase, &frame)
        .unwrap();
    device.end_scene().unwrap();
    assert_eq!(
        PHASE_INITIAL_COLOR_COPIES.load(Ordering::Relaxed) - initial_before,
        1
    );
    assert_eq!(
        PHASE_FALLBACK_COLOR_COMMITS.load(Ordering::Relaxed) - fallback_before,
        0
    );
    let readback = device
        .create_system_memory_surface(32, 24, desc.Format)
        .unwrap();
    device.copy_render_target_data(&target, &readback).unwrap();
    for pixel in readback.read_rgba8().unwrap() {
        for value in &pixel[..3] {
            assert!((*value - 128.0 / 255.0).abs() <= 1.0 / 255.0);
        }
    }
}

/// The menu releases visual resources inside the active Present transaction.
/// Exercise that shipped boundary on a real device, including draw failure.
#[test]
fn present_restores_native_state_after_visual_resource_release() {
    let _execution = RUNTIME_EXECUTION
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let owner = create_direct3d9()
        .unwrap()
        .create_windowed_device(get_desktop_window().unwrap(), 32, 24, D3DDEVTYPE_HAL)
        .unwrap();
    let device = owner.as_ref();
    let target = device.render_target(0).unwrap();
    let depth = device.depth_stencil_surface().unwrap();
    let replacement = device
        .create_render_target_texture(16, 12, D3DFMT_A8R8G8B8)
        .unwrap();
    let viewport = D3DVIEWPORT9 {
        X: 2,
        Y: 3,
        Width: 24,
        Height: 18,
        MinZ: 0.125,
        MaxZ: 0.875,
    };
    let mut runtime = ScreenShaderRuntime::default();
    for fail_draw in [false, true] {
        device.set_viewport(&viewport).unwrap();
        device.set_scissor_rect(3, 4, 20, 19).unwrap();
        device.set_render_state(D3DRS_SCISSORTESTENABLE, 1).unwrap();
        device.set_render_state(D3DRS_ZWRITEENABLE, 1).unwrap();
        let result = runtime.with_present_state(&device, |runtime| {
            device.set_depth_stencil_surface(None)?;
            device.set_render_target(0, &replacement.surface_level(0)?)?;
            device.set_render_state(D3DRS_SCISSORTESTENABLE, 0)?;
            device.set_render_state(D3DRS_ZWRITEENABLE, 0)?;
            // This is the same teardown called by the master-off menu edit.
            runtime.release_visual_resources();
            if fail_draw {
                Err(direct3d_failure())
            } else {
                Ok(())
            }
        });
        assert_eq!(
            result.is_err(),
            fail_draw,
            "menu retirement must retain restoration state"
        );
        assert_eq!(device.render_target(0).unwrap().as_raw(), target.as_raw());
        assert_eq!(
            device
                .depth_stencil_surface()
                .unwrap()
                .as_ref()
                .map(Surface9::as_raw),
            depth.as_ref().map(Surface9::as_raw)
        );
        let restored = device.viewport().unwrap();
        assert_eq!(
            (
                restored.X,
                restored.Y,
                restored.Width,
                restored.Height,
                restored.MinZ,
                restored.MaxZ
            ),
            (
                viewport.X,
                viewport.Y,
                viewport.Width,
                viewport.Height,
                viewport.MinZ,
                viewport.MaxZ
            )
        );
        let scissor = device.scissor_rect().unwrap();
        assert_eq!(
            (scissor.left, scissor.top, scissor.right, scissor.bottom),
            (3, 4, 20, 19)
        );
        assert_eq!(device.render_state(D3DRS_SCISSORTESTENABLE).unwrap(), 1);
        assert_eq!(device.render_state(D3DRS_ZWRITEENABLE).unwrap(), 1);
    }
}

/// Disabling user-facing Bloom while Halation stays enabled must keep the
/// fused final-color pipeline drawing correct output through the real
/// letterboxed phase path: every frame with a moving camera must produce a
/// fresh image (no stale reuse), the toggle must change the output, and the
/// re-enable cycle must not strand stale state. This drives the real phase
/// graph through both configurations on one device.
#[test]
fn disabling_bloom_keeps_the_final_color_output_current() {
    let _execution = RUNTIME_EXECUTION
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let owner = create_direct3d9()
        .unwrap()
        .create_windowed_device(get_desktop_window().unwrap(), 32, 24, D3DDEVTYPE_HAL)
        .unwrap();
    let device = owner.as_ref();
    let target = device.render_target(0).unwrap();
    let desc = target.desc().unwrap();
    let readback = device
        .create_system_memory_surface(32, 24, desc.Format)
        .unwrap();

    let mut config = crate::config::EmbeddedEffectsConfig::default();
    config.blooming_hdr.enabled = true;
    config.color_grade.enabled = true;
    config.color_grade.halation_enabled = true;
    config.color_grade.chromatic_aberration_enabled = true;
    let mut runtime = ScreenShaderRuntime::default();
    runtime.sources = shaders::merge_embedded_sources(&config, Vec::new())
        .into_iter()
        .filter(|source| {
            matches!(
                source.embedded_effect_kind(),
                Some(EmbeddedEffectKind::BloomingHdr) | Some(EmbeddedEffectKind::ColorGrade)
            )
        })
        .collect();
    for source in &mut runtime.sources {
        source.enabled = true;
    }
    runtime.final_color_shaders = Some(Arc::new(
        blooming_hdr::FinalColorShaderBytecode::prepare().unwrap(),
    ));
    runtime.ensure_shaders(&device);
    runtime.render_target_slots(&device).unwrap();
    let phase = ShaderPhase::FinalImageSpace;

    // Letterboxed image viewport on the full target: the shipped laptop
    // geometry (1920x1079 image on a 1920x1200 backbuffer) in miniature.
    let image_viewport = D3DVIEWPORT9 {
        X: 0,
        Y: 0,
        Width: 32,
        Height: 20,
        MinZ: 0.0,
        MaxZ: 1.0,
    };

    let mut draw_frame = |runtime: &mut ScreenShaderRuntime, epoch: u32, step: u32| {
        runtime.begin_render_epoch(epoch);
        let angle = 0.01 * step as f32;
        let frame = backend::FrameInputs {
            camera: backend::CameraFrame {
                near_z: 5.0,
                far_z: 3500.0,
                aspect_ratio: 32.0 / 20.0,
                frustum_left: -0.8,
                frustum_right: 0.8,
                frustum_bottom: -0.6,
                frustum_top: 0.6,
                world_transform: backend::CameraTransformFrame {
                    rotation: [
                        [1.0, 0.0, 0.0],
                        [0.0, angle.cos(), angle.sin()],
                        [0.0, -angle.sin(), angle.cos()],
                    ],
                    translation: [3.0, 5.0, 7.0],
                    scale: 1.0,
                    available: true,
                },
                available: true,
            },
            environment: backend::EnvironmentFrame {
                fog_color: [0.4, 0.4, 0.45],
                fog_start: 100.0,
                fog_end: 3000.0,
                fog_power: 1.0,
                fog_available: true,
            },
            sun: backend::SunFrame {
                screen_x: 0.6,
                screen_y: 0.3,
                available: true,
                daylight: 0.9,
            },
            ..backend::FrameInputs::default()
        };
        device.set_viewport(&image_viewport).unwrap();
        if runtime.phase_has_applicable_work(phase, &desc, &frame) {
            runtime
                .ensure_phase_color_copy(&device, &desc, phase)
                .unwrap();
            device.begin_scene().unwrap();
            runtime
                .draw_passes(&device, &target, &desc, phase, &frame)
                .unwrap();
            device.end_scene().unwrap();
        }
        device.copy_render_target_data(&target, &readback).unwrap();
        readback.read_rgba8().unwrap().to_vec()
    };

    let before_a = draw_frame(&mut runtime, 1, 1);
    let before_b = draw_frame(&mut runtime, 2, 2);

    // Disable user-facing Bloom; Halation must keep the pipeline alive.
    for source in &mut runtime.sources {
        if source.embedded_effect_kind() == Some(EmbeddedEffectKind::BloomingHdr) {
            source.enabled = false;
        }
    }
    runtime.rebuild_execution_plan();
    let after_a = draw_frame(&mut runtime, 3, 3);
    let after_b = draw_frame(&mut runtime, 4, 4);

    // Re-enable once more: the reported cycle must not strand stale state.
    for source in &mut runtime.sources {
        if source.embedded_effect_kind() == Some(EmbeddedEffectKind::BloomingHdr) {
            source.enabled = true;
        }
    }
    runtime.rebuild_execution_plan();
    let reenabled = draw_frame(&mut runtime, 5, 5);

    assert_ne!(
        before_a, before_b,
        "a moving camera must refresh the composed image"
    );
    assert_ne!(
        after_a, after_b,
        "a moving camera must refresh the composed image after the Bloom toggle"
    );
    assert_ne!(
        before_b, after_a,
        "the Bloom toggle must change the composed output"
    );
    assert_ne!(
        after_b, reenabled,
        "re-enabling Bloom must change the composed output again"
    );
}

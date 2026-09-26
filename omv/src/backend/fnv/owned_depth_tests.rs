//! Executable D3D9 acceptance tests for the production depth capture path.
//!
//! A real HAL device writes a texture-backed depth attachment, then the same
//! resolver used by native captures must publish stable raw R32F pixels.
//! These tests qualify the resource contract, not an unrecorded game scene.

use super::*;
use libpsycho::os::windows::{directx9::*, winapi::get_desktop_window};

// The production snapshot service has one device owner. Serialize tests that
// exercise its prepare/release lifetime, without changing production locking.
static SNAPSHOT_TEST_OWNER: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Exercise the actual snapshot service with intervening native Clear writes.
/// This measures a resource transition contract, not a substitute game frame.
#[test]
#[ignore = "explicit offline interleaved CPU/GPU benchmark"]
fn depth_snapshot_interleaved_benchmark() {
    let _owner = SNAPSHOT_TEST_OWNER.lock().unwrap();
    let _ = libpsycho::logger::Logger::new()
        .with_level(log::LevelFilter::Info)
        .init();
    depth_snapshot::prepare().unwrap();
    let owner = create_direct3d9()
        .unwrap()
        .create_windowed_device(get_desktop_window().unwrap(), 1920, 1200, D3DDEVTYPE_HAL)
        .unwrap();
    let device = owner.as_ref();
    let depth = device
        .create_depth_stencil_texture(1920, 1200, D3DFMT_INTZ)
        .unwrap();
    let surface = depth.surface_level(0).unwrap();
    device.set_depth_stencil_surface(Some(&surface)).unwrap();
    device
        .clear_attachments(D3DCLEAR_ZBUFFER as u32, 0, 0.375, 0)
        .unwrap();
    // Prepare the exact production resources outside either timed interval.
    device.begin_scene().unwrap();
    depth_snapshot::capture(&device, &surface, DepthResolveSlot::World, [1920, 1080]).unwrap();
    device.end_scene().unwrap();
    let mut timer = GpuTimer9::new(&device).ok();
    let mut captured = 0;
    for (writes, copies) in [(false, true), (true, false), (true, true)] {
        let mut cpu = [0u128; 5];
        let mut gpu = [None; 5];
        for batch in 0..5 {
            device.begin_scene().unwrap();
            if let Some(timer) = timer.as_mut() {
                timer.begin().unwrap();
            }
            let started = std::time::Instant::now();
            for _ in 0..64 {
                if writes {
                    device
                        .clear_attachments(D3DCLEAR_ZBUFFER as u32, 0, 0.375, 0)
                        .unwrap();
                }
                if copies {
                    captured = depth_snapshot::capture(
                        &device,
                        &surface,
                        DepthResolveSlot::World,
                        [1920, 1080],
                    )
                    .unwrap();
                }
            }
            cpu[batch] = started.elapsed().as_micros();
            if let Some(timer) = timer.as_mut() {
                timer.end().unwrap();
            }
            device.end_scene().unwrap();
            if let Some(timer) = timer.as_ref() {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
                loop {
                    if let Some(seconds) = timer.poll_seconds(true).unwrap() {
                        gpu[batch] = Some(seconds * 1_000_000.0);
                        break;
                    }
                    assert!(std::time::Instant::now() < deadline, "GPU query timed out");
                    std::thread::yield_now();
                }
            }
        }
        log::info!(
            "[DEPTH BENCH] 64 iterations writes={writes} copies={copies}: CPU us={cpu:?}, GPU us={gpu:?}"
        );
    }
    let texture = unsafe { Texture9::retain_raw(captured as *mut c_void) }.unwrap();
    let readback = device
        .create_system_memory_surface(1920, 1080, D3DFMT_R32F)
        .unwrap();
    device
        .copy_render_target_data(&texture.surface_level(0).unwrap(), &readback)
        .unwrap();
    assert!(
        readback
            .read_r32f()
            .unwrap()
            .iter()
            .all(|d| (*d - 0.375).abs() < 2.0 / 16777215.0)
    );
    assert!(depth_snapshot::release());
    libpsycho::logger::Logger::shutdown();
}

/// Time repeated production captures, excluding shader/resource preparation.
/// This is submission wall time on the available HAL backend, not game FPS
/// or a GPU duration. Pixel readback remains outside the timed interval.
#[test]
#[ignore = "explicit offline submission benchmark"]
fn depth_snapshot_submission_benchmark() {
    let _owner = SNAPSHOT_TEST_OWNER.lock().unwrap();
    let _ = libpsycho::logger::Logger::new()
        .with_level(log::LevelFilter::Info)
        .init();
    depth_snapshot::prepare().unwrap();
    let owner = create_direct3d9()
        .unwrap()
        .create_windowed_device(get_desktop_window().unwrap(), 1920, 1200, D3DDEVTYPE_HAL)
        .unwrap();
    let device = owner.as_ref();
    let depth = device
        .create_depth_stencil_texture(1920, 1200, D3DFMT_INTZ)
        .unwrap();
    let source = depth.surface_level(0).unwrap();
    device.set_depth_stencil_surface(Some(&source)).unwrap();
    device
        .clear_attachments(D3DCLEAR_ZBUFFER as u32, 0, 0.375, 0)
        .unwrap();
    device.begin_scene().unwrap();
    for _ in 0..16 {
        depth_snapshot::capture(&device, &source, DepthResolveSlot::World, [1920, 1080]).unwrap();
    }
    let mut samples = [0u128; 7];
    let mut captured = 0usize;
    for sample in &mut samples {
        let started = std::time::Instant::now();
        for _ in 0..128 {
            captured =
                depth_snapshot::capture(&device, &source, DepthResolveSlot::World, [1920, 1080])
                    .unwrap();
        }
        *sample = started.elapsed().as_micros();
    }
    device.end_scene().unwrap();
    let texture = unsafe { Texture9::retain_raw(captured as *mut c_void) }.unwrap();
    let readback = device
        .create_system_memory_surface(1920, 1080, D3DFMT_R32F)
        .unwrap();
    device
        .copy_render_target_data(&texture.surface_level(0).unwrap(), &readback)
        .unwrap();
    assert!(
        readback
            .read_r32f()
            .unwrap()
            .iter()
            .all(|value| (*value - 0.375).abs() < 2.0 / 16777215.0)
    );
    log::info!("[DEPTH BENCH] Seven batches of 128 captures, microseconds: {samples:?}");
    assert!(depth_snapshot::release());
    libpsycho::logger::Logger::shutdown();
}

/// The laptop report records a 1920x1080 world target sharing 1920x1200
/// depth. Exercise the actual resolver with that resource contract and the
/// recorded camera, independently of an unavailable gameplay image fixture.
#[test]
fn world_depth_accepts_color_projection_with_larger_native_backing() {
    let _owner = SNAPSHOT_TEST_OWNER.lock().unwrap();
    depth_snapshot::prepare().unwrap();
    let owner = create_direct3d9()
        .unwrap()
        .create_windowed_device(get_desktop_window().unwrap(), 1920, 1200, D3DDEVTYPE_HAL)
        .unwrap();
    let device = owner.as_ref();
    let texture = device
        .create_depth_stencil_texture(1920, 1200, D3DFMT_INTZ)
        .unwrap();
    let source = texture.surface_level(0).unwrap();
    device.set_depth_stencil_surface(Some(&source)).unwrap();
    device
        .clear_attachments(D3DCLEAR_ZBUFFER as u32, 0, 0.0, 0)
        .unwrap();
    let color = device
        .create_render_target_texture(1920, 1080, D3DFMT_A16B16G16R16F)
        .unwrap();
    device
        .set_render_target(0, &color.surface_level(0).unwrap())
        .unwrap();
    // Write the final 60 rows of the actual color image. The remaining 120
    // rows of its shared depth allocation are outside that image and stay
    // clear. Consumers sample at color-image UVs, including the last row.
    device
        .clear_attachment_rect(
            &RECT {
                left: 0,
                top: 1020,
                right: 1920,
                bottom: 1080,
            },
            D3DCLEAR_ZBUFFER as u32,
            0,
            0.75,
            0,
        )
        .unwrap();
    let camera = CameraFrame {
        available: true,
        near_z: 5.0,
        far_z: 353840.0,
        aspect_ratio: 1920.0 / 1080.0,
        frustum_left: -1.33333,
        frustum_right: 1.33333,
        frustum_bottom: -0.75,
        frustum_top: 0.75,
        ..CameraFrame::default()
    };
    let mut resolver = FnvDepthResolve::default();
    resolver.begin_epoch(1);
    device.begin_scene().unwrap();
    unsafe {
        resolver
            .resolve_from_surface(
                &device,
                owner.as_raw(),
                source.as_raw(),
                device.render_target(0).unwrap().as_raw(),
                DepthResolveSlot::World,
                DepthResolveStage::PreAlphaWorld,
                Some(camera),
                "pre-alpha publication",
                "offline native resource contract",
            )
            .unwrap();
    }
    device.end_scene().unwrap();
    assert!(
        !resolver.depth_frame().is_available(),
        "late consumers must not receive pre-alpha depth as coherent world depth"
    );
    device.begin_scene().unwrap();
    let result = unsafe {
        resolver.resolve_from_surface(
            &device,
            owner.as_raw(),
            source.as_raw(),
            device.render_target(0).unwrap().as_raw(),
            DepthResolveSlot::World,
            DepthResolveStage::CoherentWorld,
            Some(camera),
            "reported larger depth backing",
            "offline native resource contract",
        )
    };
    device.end_scene().unwrap();
    result.expect("the world projection belongs to color extent, not depth allocation extent");
    assert!(resolver.depth_frame().is_available());
    let snapshot =
        unsafe { Texture9::retain_raw(resolver.world_capture.texture_ptr as *mut c_void) }.unwrap();
    let output = snapshot.surface_level(0).unwrap();
    let output_desc = output.desc().unwrap();
    let readback = device
        .create_system_memory_surface(output_desc.Width, output_desc.Height, D3DFMT_R32F)
        .unwrap();
    device.copy_render_target_data(&output, &readback).unwrap();
    let pixels = readback.read_r32f().unwrap();
    // Observe the publication at the existing consumers' normalized sampling
    // boundary, without prescribing the provider's allocation dimensions.
    for row in 0..1080 {
        let sampled_row = ((row as f64 + 0.5) / 1080.0 * output_desc.Height as f64) as usize;
        let actual =
            pixels[sampled_row * output_desc.Width as usize + output_desc.Width as usize / 2];
        let expected = if row >= 1020 { 0.75 } else { 0.0 };
        assert!(
            (actual - expected).abs() < 2.0 / 16777215.0,
            "color row {row}: expected {expected}, got {actual}"
        );
    }
    assert!(depth_snapshot::release());
}

#[test]
fn terrain_inputs_survive_depth_adoption_and_snapshot() {
    let _owner = SNAPSHOT_TEST_OWNER.lock().unwrap();
    depth_snapshot::prepare().unwrap();
    let owner = create_direct3d9()
        .unwrap()
        .create_windowed_device(get_desktop_window().unwrap(), 16, 16, D3DDEVTYPE_HAL)
        .unwrap();
    let device = owner.as_ref();
    let source = device
        .create_depth_stencil_surface(16, 16, D3DFMT_D24S8, D3DMULTISAMPLE_NONE, 0, false)
        .unwrap();
    let clear = depth_adoption::NativeClear {
        flags: 6,
        rectangle: None,
        origin: [0, 0],
        depth: 0.25,
        stencil: 7,
    };
    let mrt_count = device.device_caps().unwrap().NumSimultaneousRTs;
    crate::effects::pbr::exercise_terrain_input_shaders(&device, || {
        let prior_depth = device.depth_stencil_surface().unwrap();
        device.set_depth_stencil_surface(Some(&source)).unwrap();
        let (texture, adopted) = depth_adoption::prepare(&device, &source, &clear, mrt_count)
            .unwrap()
            .expect("full-clear native depth can be adopted");
        assert_eq!(
            device.depth_stencil_surface().unwrap().unwrap().as_raw(),
            source.as_raw()
        );
        depth_snapshot::capture(&device, &adopted, DepthResolveSlot::World, [16, 16]).unwrap();
        assert_eq!(
            device.depth_stencil_surface().unwrap().unwrap().as_raw(),
            source.as_raw()
        );
        device
            .set_depth_stencil_surface(prior_depth.as_ref())
            .unwrap();
        drop(adopted);
        drop(texture);
    });
    assert!(depth_snapshot::release());
}

#[test]
fn texture_backed_depth_publishes_stable_raw_snapshot() {
    let _owner = SNAPSHOT_TEST_OWNER.lock().unwrap();
    depth_snapshot::prepare().expect("prepare the production snapshot shader");
    let d3d = create_direct3d9().expect("D3D9 runtime");
    let window = get_desktop_window().expect("test window");
    let owner = d3d
        .create_windowed_device(window, 32, 24, D3DDEVTYPE_HAL)
        .expect("real HAL device; NULLREF cannot qualify pixels");
    let device = owner.as_ref();
    exercise_clear_adoption(&device);
    device
        .check_depth_texture_support(D3DFMT_INTZ)
        .expect("actual-adapter INTZ support");
    device
        .check_depth_stencil_match(
            device.back_buffer(0, 0).unwrap().desc().unwrap().Format,
            D3DFMT_INTZ,
        )
        .expect("actual-adapter color/depth match");
    if std::env::var_os("OMV_DEPTH_REQUIRE_NO_RESZ").is_some() {
        assert!(!device.supports_resz().expect("query actual RESZ exposure"));
        assert!(
            NvapiDepthResolve::load().is_err(),
            "vendor copy API must be absent in this qualification run"
        );
    }
    let texture = device
        .create_depth_stencil_texture(32, 24, D3DFMT_INTZ)
        .expect("INTZ texture");
    let surface = texture.surface_level(0).expect("INTZ surface");
    device
        .set_depth_stencil_surface(Some(&surface))
        .expect("bind source");
    device
        .clear_attachments((D3DCLEAR_ZBUFFER | D3DCLEAR_STENCIL) as u32, 0, 1.0, 37)
        .expect("clear depth and stencil");
    device
        .clear_attachment_rect(
            &RECT {
                left: 0,
                top: 0,
                right: 16,
                bottom: 24,
            },
            D3DCLEAR_ZBUFFER as u32,
            0,
            0.25,
            0,
        )
        .expect("write left half depth");
    let mut resolver = FnvDepthResolve::default();
    resolver.begin_epoch(1);
    let camera = CameraFrame {
        available: true,
        near_z: 1.0,
        far_z: 1000.0,
        aspect_ratio: 32.0 / 24.0,
        frustum_left: -1.0,
        frustum_right: 1.0,
        frustum_bottom: -0.75,
        frustum_top: 0.75,
        ..CameraFrame::default()
    };
    device.begin_scene().expect("begin capture scene");
    let result = unsafe {
        resolver.resolve_from_surface(
            &device,
            owner.as_raw(),
            surface.as_raw(),
            device.render_target(0).unwrap().as_raw(),
            DepthResolveSlot::World,
            DepthResolveStage::CoherentWorld,
            Some(camera),
            "offline acceptance",
            "texture-backed native depth",
        )
    };
    device.end_scene().expect("end capture scene");
    result.expect("sampleable depth must resolve without a vendor copy dependency");
    assert_eq!(
        resolver.route.kind(),
        DepthResolveRouteKind::Unprobed,
        "owned capture must not even select a vendor copy route"
    );
    let snapshot =
        unsafe { Texture9::retain_raw(resolver.world_capture.texture_ptr as *mut c_void) }
            .expect("published snapshot");
    let output = snapshot.surface_level(0).expect("snapshot surface");
    assert_eq!(
        output.desc().expect("snapshot description").Format,
        D3DFMT_R32F
    );
    assert_eq!(
        device
            .depth_stencil_surface()
            .expect("restored depth")
            .expect("depth bound")
            .as_raw(),
        surface.as_raw()
    );
    device
        .clear_attachments(D3DCLEAR_ZBUFFER as u32, 0, 0.75, 0)
        .expect("later source overwrite");
    let readback = device
        .create_system_memory_surface(32, 24, D3DFMT_R32F)
        .expect("readback");
    device
        .copy_render_target_data(&output, &readback)
        .expect("read snapshot pixels");
    for (index, value) in readback
        .read_r32f()
        .expect("R32F pixels")
        .into_iter()
        .enumerate()
    {
        let expected = if index % 32 < 16 { 0.25 } else { 1.0 };
        assert!(
            (value - expected).abs() < 2.0 / 16777215.0,
            "pixel {index}: expected preserved {expected}, got {value}"
        );
    }
    // Native-style depth writes exercise alpha rejection and the untouched
    // stencil plane. The fixture only generates input; capture uses shipped HLSL.
    let shader_code = crate::shaders::compile_hlsl_source_target(
        "depth_input.hlsl",
        b"float4 Main(float2 uv:TEXCOORD0):COLOR0 { return float4(1,1,1,step(0.5,uv.x)); }",
        "ps_3_0",
    )
    .expect("input shader");
    let shader = device
        .create_pixel_shader(&shader_code)
        .expect("input shader object");
    device.clear_vertex_shader().unwrap();
    device.set_fvf(ScreenVertex::FVF).unwrap();
    device.set_pixel_shader(&shader).unwrap();
    for (state, value) in [
        (D3DRS_ZENABLE, 1),
        (D3DRS_ZWRITEENABLE, 1),
        (D3DRS_ZFUNC, D3DCMP_LESSEQUAL.0 as u32),
        (D3DRS_STENCILENABLE, 1),
        (D3DRS_STENCILFUNC, D3DCMP_EQUAL.0 as u32),
        (D3DRS_STENCILREF, 37),
        (D3DRS_STENCILMASK, 255),
        (D3DRS_STENCILWRITEMASK, 0),
        (D3DRS_STENCILPASS, D3DSTENCILOP_KEEP.0 as u32),
        (D3DRS_ALPHATESTENABLE, 1),
        (D3DRS_ALPHAFUNC, D3DCMP_GREATER.0 as u32),
        (D3DRS_ALPHAREF, 128),
        (D3DRS_CULLMODE, D3DCULL_NONE.0 as u32),
    ] {
        device.set_render_state(state, value).unwrap();
    }
    let mut vertices = [
        ScreenVertex::new(-0.5, -0.5, 0.0, 0.0),
        ScreenVertex::new(63.5, -0.5, 2.0, 0.0),
        ScreenVertex::new(-0.5, 47.5, 0.0, 2.0),
    ];
    let mut first_person = None;
    for depth in [0.5, 0.25] {
        for vertex in &mut vertices {
            vertex.z = depth;
        }
        device.begin_scene().unwrap();
        unsafe { device.draw_primitive_up(D3DPT_TRIANGLELIST, 1, &vertices) }.unwrap();
        let native_viewport = device.viewport().unwrap();
        let native_scissor = device.scissor_rect().unwrap();
        device
            .set_viewport(&D3DVIEWPORT9 {
                X: 3,
                Y: 2,
                Width: 19,
                Height: 13,
                MinZ: 0.1,
                MaxZ: 0.9,
            })
            .unwrap();
        device.set_scissor_rect(4, 3, 17, 12).unwrap();
        device.set_texture(15, &snapshot).unwrap();
        let vertex_textures = device.device_caps().unwrap().VertexTextureFilterCaps != 0;
        if vertex_textures {
            device.set_texture(257, &snapshot).unwrap();
        }
        device
            .set_sampler_state(0, D3DSAMP_ADDRESSU, D3DTADDRESS_WRAP.0 as u32)
            .unwrap();
        let vertex_constants = [[0.125, 0.25, 0.5, 1.0]; 4];
        let pixel_constants = [[0.75, 0.5, 0.25, 0.0]; 4];
        device
            .set_vertex_shader_constant_f(200, &vertex_constants)
            .unwrap();
        device
            .set_pixel_shader_constant_f(200, &pixel_constants)
            .unwrap();
        let pointer =
            depth_snapshot::capture(&device, &surface, DepthResolveSlot::FirstPerson, [32, 24])
                .expect("first-person snapshot transport");
        let restored = device.viewport().unwrap();
        assert_eq!(
            (restored.X, restored.Y, restored.Width, restored.Height),
            (3, 2, 19, 13)
        );
        assert_eq!((restored.MinZ, restored.MaxZ), (0.1, 0.9));
        let scissor = device.scissor_rect().unwrap();
        assert_eq!(
            (scissor.left, scissor.top, scissor.right, scissor.bottom),
            (4, 3, 17, 12)
        );
        assert_eq!(device.fvf().unwrap(), ScreenVertex::FVF);
        assert_eq!(
            device.sampler_state(0, D3DSAMP_ADDRESSU).unwrap(),
            D3DTADDRESS_WRAP.0 as u32
        );
        assert_eq!(device.texture_raw(15), Some(snapshot.as_raw_base_texture()));
        if vertex_textures {
            assert_eq!(
                device.texture_raw(257),
                Some(snapshot.as_raw_base_texture())
            );
            device.clear_texture(257).unwrap();
        }
        device.clear_texture(15).unwrap();
        let mut constants = [[0.0; 4]; 4];
        device
            .vertex_shader_constant_f(200, &mut constants)
            .unwrap();
        assert_eq!(constants, vertex_constants);
        device.pixel_shader_constant_f(200, &mut constants).unwrap();
        assert_eq!(constants, pixel_constants);
        device.set_viewport(&native_viewport).unwrap();
        device
            .set_scissor_rect(
                native_scissor.left,
                native_scissor.top,
                native_scissor.right,
                native_scissor.bottom,
            )
            .unwrap();
        device.end_scene().unwrap();
        let captured = unsafe { Texture9::retain_raw(pointer as *mut c_void) }.unwrap();
        assert_ne!(
            captured.as_raw_base_texture(),
            snapshot.as_raw_base_texture()
        );
        device
            .copy_render_target_data(&captured.surface_level(0).unwrap(), &readback)
            .unwrap();
        for (index, value) in readback.read_r32f().unwrap().into_iter().enumerate() {
            let expected = if index % 32 < 16 { 0.75 } else { depth };
            assert!(
                (value - expected).abs() < 2.0 / 16777215.0,
                "native depth draw {depth}, pixel {index}: {value} != {expected}"
            );
        }
        // The next draw deliberately reuses the restored shader and render state.
        first_person = Some(captured);
    }
    device.copy_render_target_data(&output, &readback).unwrap();
    for (index, value) in readback.read_r32f().unwrap().into_iter().enumerate() {
        let expected = if index % 32 < 16 { 0.25 } else { 1.0 };
        assert!((value - expected).abs() < 2.0 / 16777215.0);
    }
    // Release all caller references as the native pre-reset notification does.
    let mut parameters = device.presentation_parameters().unwrap();
    device.set_depth_stencil_surface(None).unwrap();
    device.clear_texture(0).unwrap();
    drop(first_person);
    drop(output);
    drop(snapshot);
    drop(surface);
    drop(texture);
    assert!(depth_snapshot::release());
    parameters.BackBufferWidth = 40;
    parameters.BackBufferHeight = 30;
    unsafe { device.reset(&mut parameters) }.expect("Reset after snapshot retirement");
    let resized = device
        .create_depth_stencil_texture(40, 30, D3DFMT_INTZ)
        .unwrap();
    let resized_surface = resized.surface_level(0).unwrap();
    device
        .set_depth_stencil_surface(Some(&resized_surface))
        .unwrap();
    device
        .clear_attachments(D3DCLEAR_ZBUFFER as u32, 0, 0.625, 0)
        .unwrap();
    for (x, y, depth) in [(0, 0, 0.0), (39, 29, 1.0)] {
        device
            .clear_attachment_rect(
                &RECT {
                    left: x,
                    top: y,
                    right: x + 1,
                    bottom: y + 1,
                },
                D3DCLEAR_ZBUFFER as u32,
                0,
                depth,
                0,
            )
            .unwrap();
    }
    device
        .set_render_state(D3DRS_ZFUNC, D3DCMP_GREATER.0 as u32)
        .unwrap();
    device.begin_scene().unwrap();
    unsafe {
        resolver.resolve_from_surface(
            &device,
            owner.as_raw(),
            resized_surface.as_raw(),
            device.render_target(0).unwrap().as_raw(),
            DepthResolveSlot::World,
            DepthResolveStage::CoherentWorld,
            Some(camera),
            "resized reversed depth",
            "texture-backed native depth",
        )
    }
    .unwrap();
    assert_eq!(resolver.world_capture.projection.reversed_depth, Some(true));
    let pointer = resolver.world_capture.texture_ptr;
    device.end_scene().unwrap();
    let captured = unsafe { Texture9::retain_raw(pointer as *mut c_void) }.unwrap();
    let resized_readback = device
        .create_system_memory_surface(40, 30, D3DFMT_R32F)
        .unwrap();
    device
        .copy_render_target_data(&captured.surface_level(0).unwrap(), &resized_readback)
        .unwrap();
    for (index, value) in resized_readback
        .read_r32f()
        .unwrap()
        .into_iter()
        .enumerate()
    {
        let expected = match index {
            0 => 0.0,
            1199 => 1.0,
            _ => 0.625,
        };
        assert!(
            (value - expected).abs() < 2.0 / 16777215.0,
            "resized reversed-depth pixel {index}: {value} != {expected}"
        );
    }
    assert!(depth_snapshot::release());
}

// Run in the same real-device test as snapshots, so the process-owned capture
// service cannot be concurrently replaced by a second device in another test.
fn exercise_clear_adoption(device: &Device9Ref<'_>) {
    use super::depth_adoption::{NativeClear, prepare};
    let state = device.create_state_block(D3DSBT_ALL).unwrap();
    let original_depth = device.depth_stencil_surface().unwrap();
    let original_color = device.render_target(0).unwrap();
    let source = device
        .create_depth_stencil_surface(32, 24, D3DFMT_D24S8, D3DMULTISAMPLE_NONE, 0, false)
        .unwrap();
    device.set_depth_stencil_surface(Some(&source)).unwrap();
    device.set_render_state(D3DRS_SCISSORTESTENABLE, 0).unwrap();
    device
        .clear_attachments((D3DCLEAR_ZBUFFER | D3DCLEAR_STENCIL) as u32, 0, 0.25, 37)
        .unwrap();
    let viewport = D3DVIEWPORT9 {
        X: 3,
        Y: 2,
        Width: 19,
        Height: 13,
        MinZ: 0.0,
        MaxZ: 1.0,
    };
    device.set_viewport(&viewport).unwrap();
    let mut clear = NativeClear {
        flags: 7,
        rectangle: None,
        origin: [0, 0],
        depth: 0.625,
        stencil: 91,
    };
    let count = device.simultaneous_render_target_count().unwrap();
    for flags in [0, 1, 2, 4, 5] {
        clear.flags = flags;
        assert!(prepare(device, &source, &clear, count).unwrap().is_none());
    }
    clear.flags = 7;
    clear.rectangle = Some([0.0, 0.5, 1.0, 0.0]);
    assert!(prepare(device, &source, &clear, count).unwrap().is_none());
    clear.rectangle = None;
    clear.origin = [1, 0];
    assert!(prepare(device, &source, &clear, count).unwrap().is_none());
    clear.origin = [0, 0];
    device.set_render_state(D3DRS_SCISSORTESTENABLE, 1).unwrap();
    device.set_scissor_rect(0, 0, 16, 24).unwrap();
    assert!(prepare(device, &source, &clear, count).unwrap().is_none());
    let large = device
        .create_depth_stencil_surface(40, 30, D3DFMT_D24S8, D3DMULTISAMPLE_NONE, 0, false)
        .unwrap();
    device.set_depth_stencil_surface(Some(&large)).unwrap();
    assert!(prepare(device, &large, &clear, count).unwrap().is_none());
    device.set_depth_stencil_surface(Some(&source)).unwrap();
    device.set_scissor_rect(0, 0, 32, 24).unwrap();
    clear.rectangle = Some([0.0, 1.0, 1.0, 0.0]);
    let (texture, surface) = prepare(device, &source, &clear, count)
        .unwrap()
        .expect("full clear adopts");
    assert_eq!(
        device.depth_stencil_surface().unwrap().unwrap().as_raw(),
        source.as_raw()
    );
    let restored = device.viewport().unwrap();
    assert_eq!(
        (restored.X, restored.Y, restored.Width, restored.Height),
        (3, 2, 19, 13)
    );
    assert_eq!(device.render_state(D3DRS_SCISSORTESTENABLE).unwrap(), 1);
    assert_eq!(device.scissor_rect().unwrap().right, 32);
    device.set_depth_stencil_surface(Some(&surface)).unwrap();
    device.begin_scene().unwrap();
    let pointer =
        depth_snapshot::capture(device, &surface, DepthResolveSlot::World, [32, 24]).unwrap();
    device.end_scene().unwrap();
    let captured = unsafe { Texture9::retain_raw(pointer as *mut c_void) }.unwrap();
    let readback = device
        .create_system_memory_surface(32, 24, D3DFMT_R32F)
        .unwrap();
    device
        .copy_render_target_data(&captured.surface_level(0).unwrap(), &readback)
        .unwrap();
    assert!(
        readback
            .read_r32f()
            .unwrap()
            .into_iter()
            .all(|v| (v - 0.625).abs() <= 2.0 / 16777215.0)
    );

    // Actual stencil/depth tests verify both the candidate initialization and
    // preservation of the displaced native source, including rejected clears.
    let color = device
        .create_render_target_texture(32, 24, D3DFMT_R32F)
        .unwrap();
    device.set_depth_stencil_surface(None).unwrap();
    device
        .set_render_target(0, &color.surface_level(0).unwrap())
        .unwrap();
    let shader = crate::shaders::compile_hlsl_source_target(
        "adoption_probe.hlsl",
        b"float4 Main() : COLOR0 { return 1.0; }",
        "ps_3_0",
    )
    .unwrap();
    let shader = device.create_pixel_shader(&shader).unwrap();
    device.clear_vertex_shader().unwrap();
    device.set_fvf(ScreenVertex::FVF).unwrap();
    device.set_pixel_shader(&shader).unwrap();
    for (state, value) in [
        (D3DRS_ZENABLE, 1),
        (D3DRS_ZWRITEENABLE, 0),
        (D3DRS_ZFUNC, D3DCMP_LESSEQUAL.0 as u32),
        (D3DRS_STENCILENABLE, 1),
        (D3DRS_STENCILFUNC, D3DCMP_EQUAL.0 as u32),
        (D3DRS_STENCILMASK, 255),
        (D3DRS_STENCILWRITEMASK, 0),
        (D3DRS_STENCILPASS, D3DSTENCILOP_KEEP.0 as u32),
        (D3DRS_ALPHATESTENABLE, 0),
        (D3DRS_ALPHABLENDENABLE, 0),
        (D3DRS_SCISSORTESTENABLE, 0),
        (D3DRS_CULLMODE, D3DCULL_NONE.0 as u32),
        (D3DRS_COLORWRITEENABLE, 15),
    ] {
        device.set_render_state(state, value).unwrap();
    }
    for (depth_surface, stencil, z, expected) in [
        (&source, 37, 0.5, 0.0),
        (&source, 37, 0.125, 1.0),
        (&surface, 91, 0.5, 1.0),
        (&surface, 37, 0.5, 0.0),
    ] {
        device
            .set_depth_stencil_surface(Some(depth_surface))
            .unwrap();
        device.set_render_state(D3DRS_STENCILREF, stencil).unwrap();
        device
            .clear_attachments(D3DCLEAR_TARGET as u32, 0, 1.0, 0)
            .unwrap();
        let mut vertices = [
            ScreenVertex::new(-0.5, -0.5, 0.0, 0.0),
            ScreenVertex::new(63.5, -0.5, 2.0, 0.0),
            ScreenVertex::new(-0.5, 47.5, 0.0, 2.0),
        ];
        for vertex in &mut vertices {
            vertex.z = z;
        }
        device.begin_scene().unwrap();
        unsafe { device.draw_primitive_up(D3DPT_TRIANGLELIST, 1, &vertices) }.unwrap();
        device.end_scene().unwrap();
        device
            .copy_render_target_data(&color.surface_level(0).unwrap(), &readback)
            .unwrap();
        assert!(
            readback
                .read_r32f()
                .unwrap()
                .into_iter()
                .all(|v| v == expected),
            "depth/stencil probe: ref={stencil}, z={z}"
        );
    }
    device.set_depth_stencil_surface(None).unwrap();
    device.set_render_target(0, &original_color).unwrap();
    device
        .set_depth_stencil_surface(original_depth.as_ref())
        .unwrap();
    state.apply().unwrap();
    drop(captured);
    drop(texture);
    assert!(depth_snapshot::release());
}

/// The depth-snapshot transaction retains a compatible bound depth instead of
/// detaching and rebinding it around the draw. This proves both the retention
/// decision (driver-validated pairing, dimensions, multisample mode) and that
/// the executed capture preserves the engine's exact attachment bindings.
#[test]
fn snapshot_retains_compatible_bound_depth_and_restores_attachments() {
    let _owner = SNAPSHOT_TEST_OWNER.lock().unwrap();
    depth_snapshot::prepare().unwrap();
    let owner = create_direct3d9()
        .unwrap()
        .create_windowed_device(get_desktop_window().unwrap(), 64, 64, D3DDEVTYPE_HAL)
        .unwrap();
    let device = owner.as_ref();
    let slots = crate::render_state::RenderTargetSlots::query(&device).unwrap();

    // Positive control: an INTZ depth at least as large as the R32F target
    // and accepted by the driver's own depth-pairing query is retained.
    let depth = device
        .create_depth_stencil_texture(64, 64, D3DFMT_INTZ)
        .unwrap();
    let depth_surface = depth.surface_level(0).unwrap();
    device
        .set_depth_stencil_surface(Some(&depth_surface))
        .unwrap();
    device
        .clear_attachments(D3DCLEAR_ZBUFFER as u32, 0, 0.375, 0)
        .unwrap();
    let mut attachments = crate::render_state::RenderAttachments::capture(&device, slots).unwrap();
    attachments.retain_compatible_depth(&device, 64, 64, D3DFMT_R32F);
    assert!(
        attachments.depth_retained(),
        "a driver-validated INTZ/R32F pairing must retain its depth binding"
    );

    // Negative control: a depth smaller than the render target fails D3D9's
    // attachment rule and must keep the detach/rebind transaction.
    let small = device
        .create_depth_stencil_texture(16, 16, D3DFMT_INTZ)
        .unwrap();
    device
        .set_depth_stencil_surface(Some(&small.surface_level(0).unwrap()))
        .unwrap();
    let mut smaller_attachments =
        crate::render_state::RenderAttachments::capture(&device, slots).unwrap();
    smaller_attachments.retain_compatible_depth(&device, 64, 64, D3DFMT_R32F);
    assert!(
        !smaller_attachments.depth_retained(),
        "depth smaller than the target must not be retained"
    );
    device
        .set_depth_stencil_surface(Some(&depth_surface))
        .unwrap();

    // End-to-end: the executed capture must publish exact pixels while the
    // engine's RT0 and depth-stencil bindings come back exactly as they were.
    let color = device
        .create_render_target_texture(64, 64, D3DFMT_A8R8G8B8)
        .unwrap();
    let color_surface = color.surface_level(0).unwrap();
    device.set_render_target(0, &color_surface).unwrap();
    let original_target = device.render_target(0).unwrap();
    device.begin_scene().unwrap();
    let captured =
        depth_snapshot::capture(&device, &depth_surface, DepthResolveSlot::World, [64, 64])
            .unwrap();
    device.end_scene().unwrap();
    assert_eq!(
        device.render_target(0).unwrap().as_raw(),
        original_target.as_raw(),
        "the capture transaction must restore RT0"
    );
    assert_eq!(
        device
            .depth_stencil_surface()
            .unwrap()
            .map(|surface| surface.as_raw()),
        Some(depth_surface.as_raw()),
        "the capture transaction must restore the depth-stencil binding"
    );
    let texture = unsafe { Texture9::retain_raw(captured as *mut c_void) }.unwrap();
    let readback = device
        .create_system_memory_surface(64, 64, D3DFMT_R32F)
        .unwrap();
    device
        .copy_render_target_data(&texture.surface_level(0).unwrap(), &readback)
        .unwrap();
    assert!(
        readback
            .read_r32f()
            .unwrap()
            .iter()
            .all(|value| (*value - 0.375).abs() < 2.0 / 16777215.0),
        "retained-depth capture must publish the same exact raw depth"
    );
    assert!(depth_snapshot::release());
}

#[test]
fn snapshot_shader_has_one_sample_and_bounded_sm3_bytecode() {
    let code = crate::shaders::compile_hlsl_source_target(
        "depth_snapshot.hlsl",
        depth_snapshot::SOURCE.as_bytes(),
        "ps_3_0",
    )
    .unwrap();
    assert_eq!(code[0], 0xffff0300);
    let mut cursor = 1;
    let mut instructions = 0;
    let mut samples = 0;
    while cursor < code.len() && code[cursor] as u16 != 0xffff {
        let token = code[cursor];
        let opcode = token as u16;
        if opcode == 0xfffe {
            cursor += 1 + ((token >> 16) & 0x7fff) as usize;
            continue;
        }
        // Only DCL, MOV, and TEXLD are needed for the raw point-sampled copy.
        assert!(matches!(opcode, 31 | 1 | 66), "unexpected opcode {opcode}");
        samples += usize::from(opcode == 66);
        instructions += 1;
        cursor += 1 + ((token >> 24) & 15) as usize;
    }
    assert!(cursor < code.len(), "missing END");
    assert_eq!(samples, 1);
    assert!(
        instructions <= 6,
        "{instructions} instructions exceed the snapshot budget"
    );
}

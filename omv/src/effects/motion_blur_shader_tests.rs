//! Executes the shipped blur shaders at their D3D9 image boundary.
//!
//! Camera pairs and constants use production reprojection and binding. Input
//! textures obey the proven resolved-depth and linear scene-color contracts;
//! the test device uses the production fullscreen pass and sampler states.
//! Exposure direction is observed as the displacement of an isolated feature,
//! rather than by reproducing the shader's gather equations in Rust. Resources
//! and readbacks belong exclusively to these offline tests.

use libpsycho::os::windows::{
    directx9::{
        D3DDEVTYPE_HAL, D3DFMT_A8R8G8B8, D3DFMT_A16B16G16R16F, D3DPOOL_MANAGED, D3DSURFACE_DESC,
        Device9, create_direct3d9,
    },
    winapi::{get_active_window, get_desktop_window, get_foreground_window},
};

use super::{
    DEPTH_HISTORY_SHADER, MotionBlurSettings, MotionBlurView, MotionReprojection,
    PreparedMotionBlurFrame, TemporalCameraState, bind_constants, bind_pipeline_state, bind_target,
    draw_quad, screen_data, shader_source,
};
use crate::{
    backend::{CameraFrame, CameraTransformFrame},
    config::{MotionBlurConfig, MotionBlurQuality},
};

const WIDTH: u32 = 128;
const HEIGHT: u32 = 32;
const QUALITIES: [MotionBlurQuality; 3] = [
    MotionBlurQuality::Performance,
    MotionBlurQuality::High,
    MotionBlurQuality::Ultra,
];

fn variants() -> impl Iterator<Item = (bool, bool, MotionBlurQuality)> {
    [false, true].into_iter().flat_map(|third_person| {
        [false, true].into_iter().flat_map(move |reversed_depth| {
            QUALITIES
                .into_iter()
                .map(move |quality| (third_person, reversed_depth, quality))
        })
    })
}

fn device() -> Device9 {
    let window = [
        get_active_window(),
        get_foreground_window(),
        get_desktop_window().expect("Wine desktop window"),
    ]
    .into_iter()
    .find(|window| !window.is_null())
    .expect("Wine window for shader execution");
    create_direct3d9()
        .expect("D3D9 runtime")
        .create_windowed_device(window, WIDTH, HEIGHT, D3DDEVTYPE_HAL)
        .expect("rendering HAL; NULLREF cannot qualify an image")
}

fn camera(rotation: [[f32; 3]; 3], translation: [f32; 3]) -> CameraFrame {
    CameraFrame {
        near_z: 5.0,
        far_z: 100_000.0,
        aspect_ratio: WIDTH as f32 / HEIGHT as f32,
        frustum_left: -1.0,
        frustum_right: 1.0,
        frustum_top: 0.25,
        frustum_bottom: -0.25,
        world_transform: CameraTransformFrame {
            rotation,
            translation,
            scale: 1.0,
            available: true,
        },
        available: true,
    }
}

fn feature_pixels() -> Vec<u32> {
    (0..WIDTH * HEIGHT)
        .map(|index| {
            if index % WIDTH == WIDTH / 2 {
                0x7FFF_FFFF
            } else {
                0x7F00_0000
            }
        })
        .collect()
}

fn render(
    previous: CameraFrame,
    current: CameraFrame,
    sky: bool,
    third_person: bool,
    reversed_depth: bool,
    quality: MotionBlurQuality,
    pixels: &[u32],
) -> Vec<[f32; 4]> {
    let owner = device();
    let device = owner.as_ref();
    let color = device
        .create_texture(WIDTH, HEIGHT, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)
        .expect("scene color input");
    color
        .write_level0_argb(WIDTH, HEIGHT, pixels)
        .expect("scene texels");
    let raw_depth = if sky {
        1.0
    } else {
        // Perspective depth of a plane at z=1000, from the documented native
        // near/far contract. This is input encoding, not a blur reference.
        current.far_z * (1.0 - current.near_z / 1000.0) / (current.far_z - current.near_z)
    };
    let raw_depth = if reversed_depth {
        1.0 - raw_depth
    } else {
        raw_depth
    };
    let depth = device
        .create_dynamic_rgba32f_texture(WIDTH, HEIGHT)
        .expect("resolved-depth input");
    depth
        .write_discard(&vec![[raw_depth, 0.0, 0.0, 0.0]; pixels.len()])
        .expect("depth texels");
    let output_format = if third_person {
        D3DFMT_A8R8G8B8
    } else {
        D3DFMT_A16B16G16R16F
    };
    let output = device
        .create_render_target_texture(WIDTH, HEIGHT, output_format)
        .expect("blur output");
    let surface = output.surface_level(0).expect("blur surface");
    let desc: D3DSURFACE_DESC = surface.desc().expect("output description");
    let bytecode = crate::shaders::compile_hlsl_source_target(
        "motion-blur-image-regression",
        &shader_source(quality, third_person),
        "ps_3_0",
    )
    .expect("production blur shader");
    let shader = device
        .create_pixel_shader(&bytecode)
        .expect("blur shader object");
    let frame = PreparedMotionBlurFrame {
        settings: MotionBlurSettings::from_config(MotionBlurConfig {
            quality,
            ..MotionBlurConfig::default()
        }),
        current_world: current,
        world_reprojection: MotionReprojection::between(
            TemporalCameraState {
                camera: previous,
                epoch: 1,
            },
            TemporalCameraState {
                camera: current,
                epoch: 2,
            },
        ),
        world_reversed: reversed_depth,
        capture_epoch: 2,
        view: if third_person {
            MotionBlurView::ThirdPersonWorld
        } else {
            MotionBlurView::FirstPersonWorld
        },
        blur_requested: true,
    };
    device.begin_scene().expect("begin blur scene");
    let history = if third_person {
        let history = device
            .create_render_target_texture(WIDTH, HEIGHT, D3DFMT_A8R8G8B8)
            .expect("production packed depth history");
        let history_surface = history.surface_level(0).expect("history surface");
        let history_code = crate::shaders::compile_hlsl_source_target(
            "motion-blur-history-regression",
            DEPTH_HISTORY_SHADER,
            "ps_3_0",
        )
        .expect("production depth packing shader");
        let history_shader = device
            .create_pixel_shader(&history_code)
            .expect("depth packing object");
        bind_pipeline_state(&device).expect("history pass state");
        bind_target(&device, &history_surface, &history_surface.desc().unwrap())
            .expect("history target");
        device
            .set_texture(0, depth.texture())
            .expect("history depth input");
        device
            .set_pixel_shader_constant_f(0, &[screen_data(&desc)])
            .expect("history dimensions");
        device
            .set_pixel_shader(&history_shader)
            .expect("history shader binding");
        draw_quad(&device, &desc).expect("production history draw");
        Some(history)
    } else {
        None
    };
    bind_pipeline_state(&device).expect("production sampler and render state");
    bind_target(&device, &surface, &desc).expect("production output binding");
    device.set_texture(0, &color).expect("scene sampler");
    device
        .set_texture(1, depth.texture())
        .expect("depth sampler");
    if let Some(history) = &history {
        device.set_texture(3, history).expect("history sampler");
    }
    bind_constants(&device, &desc, frame, third_person, reversed_depth)
        .expect("production camera constants");
    device
        .set_pixel_shader(&shader)
        .expect("blur shader binding");
    draw_quad(&device, &desc).expect("production fullscreen draw");
    device.end_scene().expect("end blur scene");
    let readback = device
        .create_system_memory_surface(WIDTH, HEIGHT, output_format)
        .expect("readback surface");
    device
        .copy_render_target_data(&surface, &readback)
        .expect("GPU readback");
    if third_person {
        readback.read_rgba8()
    } else {
        readback.read_rgba16f()
    }
    .expect("observed blur pixels")
}

#[test]
fn shipped_shutter_trails_a_translated_feature_toward_its_previous_position() {
    let identity = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
    let previous = camera(identity, [0.0; 3]);
    let current = camera(identity, [0.0, 0.0, 125.0]);
    let reprojection = MotionReprojection::between(
        TemporalCameraState {
            camera: previous,
            epoch: 1,
        },
        TemporalCameraState {
            camera: current,
            epoch: 2,
        },
    )
    .expect("consecutive translating camera");
    let current_uv = [(WIDTH / 2) as f32 / WIDTH as f32, 0.5];
    let previous_uv = reprojection
        .previous_uv(current, current_uv, 1000.0, true)
        .expect("native camera projection");
    assert!((previous_uv[0] - current_uv[0]) * WIDTH as f32 > 7.9);
    for (third_person, reversed_depth, quality) in variants() {
        let output = render(
            previous,
            current,
            false,
            third_person,
            reversed_depth,
            quality,
            &feature_pixels(),
        );
        let row = &output[(HEIGHT / 2 * WIDTH) as usize..((HEIGHT / 2 + 1) * WIDTH) as usize];
        let energy: f32 = row.iter().map(|pixel| pixel[0]).sum();
        let centroid = row
            .iter()
            .enumerate()
            .map(|(x, pixel)| x as f32 * pixel[0])
            .sum::<f32>()
            / energy;
        assert!(
            centroid > WIDTH as f32 / 2.0 + 2.0,
            "exposure led the moving feature: third_person={third_person}, reversed={reversed_depth}, quality={quality:?}, centroid={centroid}, energy={energy}"
        );
        assert!(output.iter().flatten().all(|channel| channel.is_finite()));
        assert!(
            output
                .iter()
                .all(|pixel| (pixel[3] - 127.0 / 255.0).abs() < 0.001)
        );
    }
}

#[test]
fn shipped_sky_rotation_blurs_independently_of_the_geometry_near_plane() {
    let identity = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
    let angle = 0.06f32;
    let rotation = [
        [angle.cos(), 0.0, angle.sin()],
        [0.0, 1.0, 0.0],
        [-angle.sin(), 0.0, angle.cos()],
    ];
    for (third_person, reversed_depth, quality) in variants() {
        let output = render(
            camera(identity, [0.0; 3]),
            camera(rotation, [0.0; 3]),
            true,
            third_person,
            reversed_depth,
            quality,
            &feature_pixels(),
        );
        let changed = output
            .iter()
            .enumerate()
            .filter(|(index, pixel)| {
                let original = if *index as u32 % WIDTH == WIDTH / 2 {
                    1.0
                } else {
                    0.0
                };
                (pixel[0] - original).abs() > 0.01
            })
            .count();
        assert!(
            changed > HEIGHT as usize,
            "sky rotation was rejected by the geometry near plane: third_person={third_person}, reversed={reversed_depth}, quality={quality:?}, changed={changed}"
        );
        assert!(output.iter().flatten().all(|channel| channel.is_finite()));
    }
}

#[test]
fn shipped_offscreen_reprojection_preserves_the_diagonal_motion_direction() {
    let identity = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
    let previous = camera(identity, [0.0; 3]);
    let current = camera(identity, [0.0, 125.0, 125.0]);
    let reprojection = MotionReprojection::between(
        TemporalCameraState {
            camera: previous,
            epoch: 1,
        },
        TemporalCameraState {
            camera: current,
            epoch: 2,
        },
    )
    .expect("diagonal camera translation");
    let (x, y) = (123, 10);
    let uv = [
        (x as f32 + 0.5) / WIDTH as f32,
        (y as f32 + 0.5) / HEIGHT as f32,
    ];
    let previous_uv = reprojection.previous_uv(current, uv, 1000.0, true).unwrap();
    assert!(previous_uv[0] > 1.0);
    let displacement = [
        (previous_uv[0] - uv[0]) * WIDTH as f32,
        (previous_uv[1] - uv[1]) * HEIGHT as f32,
    ];
    assert!((displacement[0] + displacement[1]).abs() < 0.001);
    // Equal red/green increments per pixel turn a 45-degree gather into equal
    // and opposite color changes. This tests direction, not a mirrored filter.
    let pixels = (0..WIDTH * HEIGHT)
        .map(|index| 0x7F00_0000 | ((index % WIDTH) * 2 << 16) | ((index / WIDTH) * 2 << 8))
        .collect::<Vec<_>>();
    let output = render(
        previous,
        current,
        false,
        false,
        false,
        MotionBlurQuality::High,
        &pixels,
    );
    let pixel = output[(y * WIDTH + x) as usize];
    let delta = [
        pixel[0] - (x * 2) as f32 / 255.0,
        pixel[1] - (y * 2) as f32 / 255.0,
    ];
    assert!(
        delta[0] < -0.02 && delta[1] > 0.02 && (delta[0] + delta[1]).abs() < 0.002,
        "offscreen previous UV bent the shutter: delta={delta:?}"
    );
    // The retained third-person route additionally needs previous visibility.
    // Its packed border texel may match the plane, but the feature itself was
    // outside the previous image and cannot acquire a fabricated history match.
    let output = render(
        previous,
        current,
        false,
        true,
        false,
        MotionBlurQuality::High,
        &pixels,
    );
    let pixel = output[(y * WIDTH + x) as usize];
    assert!((pixel[0] - (x * 2) as f32 / 255.0).abs() < 0.001);
    assert!((pixel[1] - (y * 2) as f32 / 255.0).abs() < 0.001);
}

#[test]
fn shipped_stationary_camera_and_translation_only_sky_preserve_color() {
    let identity = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
    let previous = camera(identity, [0.0; 3]);
    let pixels = feature_pixels();
    for third_person in [false, true] {
        for (current, sky) in [
            (previous, false),
            (camera(identity, [0.0, 0.0, 125.0]), true),
        ] {
            let output = render(
                previous,
                current,
                sky,
                third_person,
                false,
                MotionBlurQuality::High,
                &pixels,
            );
            for (index, pixel) in output.iter().enumerate() {
                let expected = if index as u32 % WIDTH == WIDTH / 2 {
                    1.0
                } else {
                    0.0
                };
                assert!(
                    pixel[..3]
                        .iter()
                        .all(|channel| (*channel - expected).abs() < 0.001)
                );
                assert!((pixel[3] - 127.0 / 255.0).abs() < 0.001);
            }
        }
    }
}

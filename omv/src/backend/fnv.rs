//! Fallout New Vegas backend.

use core::{ffi::c_void, fmt, mem::size_of};
use std::sync::{
    LazyLock,
    atomic::{AtomicU32, Ordering},
};

use super::{
    CameraFrame, CameraTransformFrame, DepthFrame, DepthProjectionFrame, DepthProvider,
    DepthResolveSlot, DepthTexture, EnvironmentFrame, MaterialStateFrame, NativeSkyFrame, SunFrame,
    UnderwaterFrame,
};
use libpsycho::os::windows::{
    directx9::{
        D3DCULL_NONE, D3DFMT_INTZ, D3DPT_POINTLIST, D3DRESZ_POINT_SIZE, D3DRS_ALPHABLENDENABLE,
        D3DRS_ALPHATESTENABLE, D3DRS_COLORWRITEENABLE, D3DRS_CULLMODE, D3DRS_POINTSIZE,
        D3DRS_ZENABLE, D3DRS_ZFUNC, D3DRS_ZWRITEENABLE, D3DSBT_ALL, D3DSURFACE_DESC, Device9Ref,
        Direct3DError as WindowsError, Direct3DResult, PositionVertex, StateBlock9, Surface9,
        Texture9,
    },
    memory::validate_memory_range,
};
use parking_lot::Mutex;

const NIDX9_RENDERER_SINGLETON_PTR: usize = 0x011C73B4;
const NIDX9_RENDERER_DEVICE_OFFSET: usize = 0x288;
const NIDX9_RENDERER_Z_CLEAR_OFFSET: usize = 0x5E4;
const BSSHADERMANAGER_CAMERA_PTR: usize = 0x011F917C;
// Main retains the SceneGraph named "World" here. The shader-manager camera is
// phase-mutable and cannot be paired reliably with the resolved world depth.
const WORLD_SCENE_GRAPH_PTR: usize = 0x011DEB7C;
const BSSHADERMANAGER_CURRENT_RENDER_TARGET_PTR: usize = 0x011F9438;
const BSSHADERMANAGER_SCENE_GRAPH_INDEX: usize = 0x011F91C4;
const BSSHADERMANAGER_SHADOW_SCENE_NODE_ARRAY: usize = 0x011F91C8;
const BSSHADERMANAGER_SHADOW_SCENE_NODE_COUNT: usize = 4;
const PLAYER_CHARACTER_PTR: usize = 0x011DEA3C;
const SKY_SINGLETON_PTR: usize = 0x011DEA20;
const TIME_GLOBALS_BASE: usize = 0x011DE7B8;
const TIME_GLOBALS_GAME_HOUR_OFFSET: usize = 0x0C;
const SKY_CLIMATE_OFFSET: usize = 0x0C;
const SKY_SUN_OFFSET: usize = 0x28;
const SKY_OBJECT_ROOT_NODE_OFFSET: usize = 0x04;
const SKY_GAME_HOUR_OFFSET: usize = 0xEC;
const SKY_UPPER_COLOR_OFFSET: usize = 0x3C;
const SKY_SUN_DIRECTIONAL_COLOR_OFFSET: usize = 0x6C;
const SKY_SUN_DISK_COLOR_OFFSET: usize = 0x78;
const SKY_LOWER_COLOR_OFFSET: usize = 0x90;
const SKY_HORIZON_COLOR_OFFSET: usize = 0x9C;
const CLIMATE_SUN_TIME_BYTES_OFFSET: usize = 0x50;
const CLIMATE_SUN_TIME_BYTES_LEN: usize = 4;
const CACHED_SUNRISE_BEGIN: usize = 0x011CA9E8;
const CACHED_SUNRISE_END: usize = 0x011CA9EC;
const CACHED_SUNSET_BEGIN: usize = 0x011CA9F0;
const CACHED_SUNSET_END: usize = 0x011CA9F4;
const SKY_SUN_TIME_DIVISOR: usize = 0x01034208;
const NATIVE_SUN_SCREEN_X_ADDR: usize = 0x012023F4;
const NATIVE_SUN_SCREEN_Y_ADDR: usize = 0x012023F8;

const NIAVOBJECT_LOCAL_TRANSLATION_OFFSET: usize = 0x58;
const NIAVOBJECT_WORLD_ROTATION_OFFSET: usize = 0x68;
const NIAVOBJECT_WORLD_TRANSLATION_OFFSET: usize = 0x8C;
const NIAVOBJECT_WORLD_SCALE_OFFSET: usize = 0x98;
const SCENE_GRAPH_CAMERA_OFFSET: usize = 0xAC;
const NICAMERA_FRUSTUM_LEFT_OFFSET: usize = 0xDC;
const NICAMERA_FRUSTUM_RIGHT_OFFSET: usize = 0xE0;
const NICAMERA_FRUSTUM_TOP_OFFSET: usize = 0xE4;
const NICAMERA_FRUSTUM_BOTTOM_OFFSET: usize = 0xE8;
const NICAMERA_FRUSTUM_NEAR_OFFSET: usize = 0xEC;
const NICAMERA_FRUSTUM_FAR_OFFSET: usize = 0xF0;
const BSRENDEREDTEXTURE_SIZE: usize = 0x40;
const BSRENDEREDTEXTURE_RENDER_TARGET_GROUP0_OFFSET: usize = 0x08;
const NIRENDERTARGETGROUP_SIZE: usize = 0x28;
const NIRENDERTARGETGROUP_BUFFER0_OFFSET: usize = 0x0C;
const NIRENDERTARGETGROUP_BUFFER_COUNT_OFFSET: usize = 0x1C;
const NIRENDERTARGETGROUP_DEPTH_BUFFER_OFFSET: usize = 0x20;
const NI2DBUFFER_SIZE: usize = 0x14;
const NI2DBUFFER_RENDERER_DATA_OFFSET: usize = 0x10;
const NIDX9_TEXTURE_BUFFER_DATA_SURFACE_OFFSET: usize = 0x14;
const SHADOW_SCENE_NODE_FOG_PROPERTY_OFFSET: usize = 0x134;
const BSFOGPROPERTY_VTABLE: usize = 0x010B9E38;
const BSFOGPROPERTY_SIZE: usize = 0x64;
const BSFOGPROPERTY_COLOR_OFFSET: usize = 0x20;
const BSFOGPROPERTY_START_DISTANCE_OFFSET: usize = 0x2C;
const BSFOGPROPERTY_END_DISTANCE_OFFSET: usize = 0x30;
const BSFOGPROPERTY_POWER_OFFSET: usize = 0x60;
const TESOBJECTREFR_PARENT_CELL_OFFSET: usize = 0x40;
const TESOBJECTCELL_FLAGS0_OFFSET: usize = 0x24;
const TESOBJECTCELL_WORLDSPACE_OFFSET: usize = 0xC0;
const TESOBJECTCELL_FLAGS0_INTERIOR: u8 = 1 << 0;
const NATIVE_SKY_READ_SIZE: usize = SKY_GAME_HOUR_OFFSET + size_of::<f32>();
const NATIVE_SUN_READ_SIZE: usize = SKY_OBJECT_ROOT_NODE_OFFSET + size_of::<usize>();
const NATIVE_SUN_ROOT_READ_SIZE: usize = NIAVOBJECT_LOCAL_TRANSLATION_OFFSET + 3 * size_of::<f32>();
const NATIVE_PLAYER_READ_SIZE: usize = TESOBJECTREFR_PARENT_CELL_OFFSET + size_of::<usize>();
const NATIVE_CELL_READ_SIZE: usize = TESOBJECTCELL_FLAGS0_OFFSET + size_of::<u8>();
const CACHED_DAYLIGHT_TIMES_SIZE: usize =
    CACHED_SUNSET_END + size_of::<f32>() - CACHED_SUNRISE_BEGIN;
const MAX_DEPTH_RESOLVE_LOGS: u32 = 16;
const FRAME_CONTRACT_LOG_INTERVAL: u32 = 120;
const MAX_FRAME_CONTRACT_LOGS: u32 = 32;

static DEPTH_RESOLVE_LOGS: AtomicU32 = AtomicU32::new(0);
static SUN_FRAME_CALLS: AtomicU32 = AtomicU32::new(0);
static SUN_FRAME_LOGS: AtomicU32 = AtomicU32::new(0);
static DEPTH_RESOLVE: LazyLock<Mutex<FnvDepthResolve>> =
    LazyLock::new(|| Mutex::new(FnvDepthResolve::default()));

pub(super) fn d3d_device_ptr() -> Option<*mut c_void> {
    unsafe {
        let renderer = read_ptr(NIDX9_RENDERER_SINGLETON_PTR)?;
        if renderer.is_null() {
            return None;
        }

        read_ptr(renderer as usize + NIDX9_RENDERER_DEVICE_OFFSET).and_then(|device| {
            if device.is_null() {
                None
            } else {
                Some(device.cast::<c_void>())
            }
        })
    }
}

pub(super) fn camera_frame(desc: &D3DSURFACE_DESC) -> CameraFrame {
    unsafe { read_camera_frame(desc).unwrap_or_else(|| CameraFrame::fallback(desc)) }
}

pub(super) fn environment_frame() -> EnvironmentFrame {
    unsafe { read_environment_frame().unwrap_or_default() }
}

pub(super) fn sun_frame() -> SunFrame {
    unsafe { read_sun_frame().unwrap_or_default() }
}

pub(super) fn material_state_frame() -> MaterialStateFrame {
    unsafe { read_material_state_frame().unwrap_or_default() }
}

pub(super) fn native_sky_frame() -> Option<NativeSkyFrame> {
    unsafe { read_native_sky_frame() }
}

pub(super) fn depth_frame() -> DepthFrame {
    DEPTH_RESOLVE.lock().depth_frame()
}

pub(super) fn publish_underwater_classification(underwater: bool) {
    DEPTH_RESOLVE
        .lock()
        .publish_underwater_classification(underwater);
}

pub(super) fn underwater_frame() -> UnderwaterFrame {
    DEPTH_RESOLVE.lock().underwater_frame()
}

pub(super) fn temporal_depth_epoch(
    device_ptr: *mut c_void,
    width: u32,
    height: u32,
) -> Option<u64> {
    DEPTH_RESOLVE
        .lock()
        .temporal_depth_epoch(device_ptr, width, height)
}

pub(super) fn world_camera_frame(width: u32, height: u32) -> Option<CameraFrame> {
    let desc = D3DSURFACE_DESC {
        Width: width,
        Height: height,
        ..D3DSURFACE_DESC::default()
    };
    unsafe { read_world_camera_frame(&desc) }
}

pub(crate) struct WorldCameraJitter {
    camera: *mut u8,
    frustum: [f32; 4],
}

impl Drop for WorldCameraJitter {
    fn drop(&mut self) {
        unsafe {
            self.camera
                .add(NICAMERA_FRUSTUM_LEFT_OFFSET)
                .cast::<f32>()
                .write(self.frustum[0]);
            self.camera
                .add(NICAMERA_FRUSTUM_RIGHT_OFFSET)
                .cast::<f32>()
                .write(self.frustum[1]);
            self.camera
                .add(NICAMERA_FRUSTUM_TOP_OFFSET)
                .cast::<f32>()
                .write(self.frustum[2]);
            self.camera
                .add(NICAMERA_FRUSTUM_BOTTOM_OFFSET)
                .cast::<f32>()
                .write(self.frustum[3]);
        }
    }
}

pub(super) unsafe fn jitter_world_camera(
    jitter_pixels: [f32; 2],
    width: u32,
    height: u32,
) -> Option<WorldCameraJitter> {
    if width == 0 || height == 0 || !jitter_pixels.iter().all(|value| value.is_finite()) {
        return None;
    }

    let scene_graph = unsafe { read_ptr(WORLD_SCENE_GRAPH_PTR)? };
    if scene_graph.is_null() {
        return None;
    }
    let camera = unsafe { read_ptr(scene_graph as usize + SCENE_GRAPH_CAMERA_OFFSET)? };
    if camera.is_null() {
        return None;
    }
    validate_memory_range(
        unsafe { camera.add(NICAMERA_FRUSTUM_LEFT_OFFSET) }.cast::<c_void>(),
        NICAMERA_FRUSTUM_BOTTOM_OFFSET + size_of::<f32>() - NICAMERA_FRUSTUM_LEFT_OFFSET,
    )
    .ok()?;

    let frustum = [
        unsafe {
            camera
                .add(NICAMERA_FRUSTUM_LEFT_OFFSET)
                .cast::<f32>()
                .read()
        },
        unsafe {
            camera
                .add(NICAMERA_FRUSTUM_RIGHT_OFFSET)
                .cast::<f32>()
                .read()
        },
        unsafe { camera.add(NICAMERA_FRUSTUM_TOP_OFFSET).cast::<f32>().read() },
        unsafe {
            camera
                .add(NICAMERA_FRUSTUM_BOTTOM_OFFSET)
                .cast::<f32>()
                .read()
        },
    ];
    if !frustum.iter().all(|value| value.is_finite())
        || frustum[1] <= frustum[0]
        || frustum[2] <= frustum[3]
    {
        return None;
    }

    let offset_x = (frustum[1] - frustum[0]) * jitter_pixels[0] / width as f32;
    let offset_y = (frustum[2] - frustum[3]) * jitter_pixels[1] / height as f32;
    unsafe {
        camera
            .add(NICAMERA_FRUSTUM_LEFT_OFFSET)
            .cast::<f32>()
            .write(frustum[0] + offset_x);
        camera
            .add(NICAMERA_FRUSTUM_RIGHT_OFFSET)
            .cast::<f32>()
            .write(frustum[1] + offset_x);
        camera
            .add(NICAMERA_FRUSTUM_TOP_OFFSET)
            .cast::<f32>()
            .write(frustum[2] - offset_y);
        camera
            .add(NICAMERA_FRUSTUM_BOTTOM_OFFSET)
            .cast::<f32>()
            .write(frustum[3] - offset_y);
    }

    Some(WorldCameraJitter { camera, frustum })
}

pub(super) fn rendered_texture_color_surface(rendered_texture: *mut c_void) -> Option<*mut c_void> {
    unsafe { read_rendered_texture_color_surface(rendered_texture).ok() }
}

pub(super) unsafe fn resolve_scene_depth(
    device_ptr: *mut c_void,
    source_rendered_texture: Option<*mut c_void>,
    slot: DepthResolveSlot,
    reason: &'static str,
) -> bool {
    let mut resolve = DEPTH_RESOLVE.lock();
    match unsafe { resolve.resolve(device_ptr, source_rendered_texture, slot, reason) } {
        Ok(()) => true,
        Err(err) => {
            resolve.invalidate_capture(slot);
            log_depth_resolve_skip(slot, reason, &err);
            false
        }
    }
}

pub(super) fn finish_frame() {
    DEPTH_RESOLVE.lock().finish_frame();
}

pub(super) fn reset_depth_resources() {
    DEPTH_RESOLVE.lock().release();
}

unsafe fn read_ptr(address: usize) -> Option<*mut u8> {
    unsafe { read_ptr_checked(address, "unreadable pointer").ok() }
}

unsafe fn read_ptr_checked(address: usize, cause: &'static str) -> Result<*mut u8, &'static str> {
    let slot = address as *const c_void;
    validate_memory_range(slot, size_of::<*mut u8>()).map_err(|_| cause)?;
    Ok(unsafe { (address as *const *mut u8).read() })
}

unsafe fn read_f32(address: usize) -> Option<f32> {
    let slot = address as *const c_void;
    validate_memory_range(slot, size_of::<f32>()).ok()?;
    Some(unsafe { (address as *const f32).read() })
}

unsafe fn read_f64(address: usize) -> Option<f64> {
    let slot = address as *const c_void;
    validate_memory_range(slot, size_of::<f64>()).ok()?;
    Some(unsafe { (address as *const f64).read() })
}

unsafe fn read_u8(address: usize) -> Option<u8> {
    let slot = address as *const c_void;
    validate_memory_range(slot, size_of::<u8>()).ok()?;
    Some(unsafe { (address as *const u8).read() })
}

unsafe fn read_u32(address: usize) -> Option<u32> {
    let slot = address as *const c_void;
    validate_memory_range(slot, size_of::<u32>()).ok()?;
    Some(unsafe { (address as *const u32).read() })
}

unsafe fn read_camera_frame(desc: &D3DSURFACE_DESC) -> Option<CameraFrame> {
    let camera = unsafe { read_ptr(BSSHADERMANAGER_CAMERA_PTR)? };
    unsafe { read_camera_frame_from_ptr(camera, desc) }
}

unsafe fn read_world_camera_frame(desc: &D3DSURFACE_DESC) -> Option<CameraFrame> {
    let scene_graph = unsafe { read_ptr(WORLD_SCENE_GRAPH_PTR)? };
    unsafe { read_scene_graph_camera_frame(scene_graph.cast(), desc) }
}

unsafe fn read_scene_graph_camera_frame(
    scene_graph: *mut c_void,
    desc: &D3DSURFACE_DESC,
) -> Option<CameraFrame> {
    if scene_graph.is_null() {
        return None;
    }

    let camera = unsafe { read_ptr(scene_graph as usize + SCENE_GRAPH_CAMERA_OFFSET)? };
    unsafe { read_camera_frame_from_ptr(camera, desc) }
}

unsafe fn read_camera_frame_from_ptr(
    camera: *mut u8,
    desc: &D3DSURFACE_DESC,
) -> Option<CameraFrame> {
    if camera.is_null() {
        return None;
    }

    validate_memory_range(
        unsafe { camera.add(NIAVOBJECT_WORLD_ROTATION_OFFSET) }.cast::<c_void>(),
        NICAMERA_FRUSTUM_FAR_OFFSET + size_of::<f32>() - NIAVOBJECT_WORLD_ROTATION_OFFSET,
    )
    .ok()?;

    let read_camera_f32 = |offset| unsafe { camera.add(offset).cast::<f32>().read() };
    let near_z = read_camera_f32(NICAMERA_FRUSTUM_NEAR_OFFSET);
    let far_z = read_camera_f32(NICAMERA_FRUSTUM_FAR_OFFSET);
    let frustum_left = read_camera_f32(NICAMERA_FRUSTUM_LEFT_OFFSET);
    let frustum_right = read_camera_f32(NICAMERA_FRUSTUM_RIGHT_OFFSET);
    let frustum_top = read_camera_f32(NICAMERA_FRUSTUM_TOP_OFFSET);
    let frustum_bottom = read_camera_f32(NICAMERA_FRUSTUM_BOTTOM_OFFSET);
    if !near_z.is_finite()
        || !far_z.is_finite()
        || !frustum_left.is_finite()
        || !frustum_right.is_finite()
        || !frustum_top.is_finite()
        || !frustum_bottom.is_finite()
        || near_z <= 0.0
        || far_z <= near_z
        || frustum_right <= frustum_left
        || frustum_top <= frustum_bottom
    {
        return None;
    }

    let aspect_ratio = if desc.Height > 0 {
        desc.Width as f32 / desc.Height as f32
    } else {
        1.0
    };
    let world_transform = unsafe { read_camera_world_transform_unchecked(camera) };
    Some(CameraFrame {
        near_z,
        far_z,
        aspect_ratio,
        frustum_left,
        frustum_right,
        frustum_bottom,
        frustum_top,
        world_transform,
        available: true,
    })
}

unsafe fn read_camera_world_transform_unchecked(camera: *mut u8) -> CameraTransformFrame {
    let rotation_address = camera as usize + NIAVOBJECT_WORLD_ROTATION_OFFSET;
    let rotation = [
        unsafe { read_vec3_unchecked(rotation_address) },
        unsafe { read_vec3_unchecked(rotation_address + 3 * size_of::<f32>()) },
        unsafe { read_vec3_unchecked(rotation_address + 6 * size_of::<f32>()) },
    ];
    let translation =
        unsafe { read_vec3_unchecked(camera as usize + NIAVOBJECT_WORLD_TRANSLATION_OFFSET) };
    let scale = unsafe {
        camera
            .add(NIAVOBJECT_WORLD_SCALE_OFFSET)
            .cast::<f32>()
            .read()
    };
    if !rotation
        .iter()
        .flatten()
        .chain(translation.iter())
        .all(|component| component.is_finite())
        || !scale.is_finite()
        || scale.abs() <= f32::EPSILON
    {
        return CameraTransformFrame::default();
    }

    CameraTransformFrame {
        rotation,
        translation,
        scale,
        available: true,
    }
}

unsafe fn read_rendered_texture_color_surface(
    rendered_texture: *mut c_void,
) -> Result<*mut c_void, &'static str> {
    let group = unsafe { read_rendered_texture_group(rendered_texture)? };

    let buffer_count =
        unsafe { read_u32(group as usize + NIRENDERTARGETGROUP_BUFFER_COUNT_OFFSET) }
            .ok_or("unreadable render target buffer count")?;
    if buffer_count == 0 {
        return Err("render target group has no color buffers");
    }

    let buffer = unsafe {
        read_ptr_checked(
            group as usize + NIRENDERTARGETGROUP_BUFFER0_OFFSET,
            "missing render target color buffer",
        )?
    };
    unsafe { read_ni_buffer_surface(buffer, "color buffer") }
}

unsafe fn read_rendered_texture_depth_surface(
    rendered_texture: *mut c_void,
) -> Result<*mut c_void, &'static str> {
    let group = unsafe { read_rendered_texture_group(rendered_texture)? };
    let buffer = unsafe {
        read_ptr_checked(
            group as usize + NIRENDERTARGETGROUP_DEPTH_BUFFER_OFFSET,
            "missing render target depth buffer",
        )?
    };
    unsafe { read_ni_buffer_surface(buffer, "depth buffer") }
}

unsafe fn read_rendered_texture_group(
    rendered_texture: *mut c_void,
) -> Result<*mut u8, &'static str> {
    if rendered_texture.is_null() {
        return Err("missing rendered texture");
    }
    validate_memory_range(rendered_texture.cast_const(), BSRENDEREDTEXTURE_SIZE)
        .map_err(|_| "unreadable rendered texture")?;

    let group = unsafe {
        read_ptr_checked(
            rendered_texture as usize + BSRENDEREDTEXTURE_RENDER_TARGET_GROUP0_OFFSET,
            "missing render target group",
        )?
    };
    if group.is_null() {
        return Err("missing render target group");
    }
    validate_memory_range(group as *const c_void, NIRENDERTARGETGROUP_SIZE)
        .map_err(|_| "unreadable render target group")?;

    Ok(group)
}

unsafe fn read_ni_buffer_surface(
    buffer: *mut u8,
    label: &'static str,
) -> Result<*mut c_void, &'static str> {
    if buffer.is_null() {
        return Err(match label {
            "depth buffer" => "missing render target depth buffer",
            _ => "missing render target color buffer",
        });
    }
    validate_memory_range(buffer as *const c_void, NI2DBUFFER_SIZE).map_err(|_| match label {
        "depth buffer" => "unreadable render target depth buffer",
        _ => "unreadable render target color buffer",
    })?;

    let renderer_data = unsafe {
        read_ptr_checked(
            buffer as usize + NI2DBUFFER_RENDERER_DATA_OFFSET,
            match label {
                "depth buffer" => "missing depth buffer renderer data",
                _ => "missing color buffer renderer data",
            },
        )?
    };
    if renderer_data.is_null() {
        return Err(match label {
            "depth buffer" => "missing depth buffer renderer data",
            _ => "missing color buffer renderer data",
        });
    }

    let surface = unsafe {
        read_ptr_checked(
            renderer_data as usize + NIDX9_TEXTURE_BUFFER_DATA_SURFACE_OFFSET,
            match label {
                "depth buffer" => "missing depth buffer D3D surface",
                _ => "missing color buffer D3D surface",
            },
        )?
    };
    if surface.is_null() {
        return Err(match label {
            "depth buffer" => "missing depth buffer D3D surface",
            _ => "missing color buffer D3D surface",
        });
    }
    validate_memory_range(surface as *const c_void, size_of::<*mut c_void>()).map_err(|_| {
        match label {
            "depth buffer" => "unreadable depth buffer D3D surface",
            _ => "unreadable color buffer D3D surface",
        }
    })?;

    Ok(surface.cast::<c_void>())
}

unsafe fn read_environment_frame() -> Option<EnvironmentFrame> {
    let scene_index = unsafe { read_u8(BSSHADERMANAGER_SCENE_GRAPH_INDEX)? } as usize;
    if scene_index >= BSSHADERMANAGER_SHADOW_SCENE_NODE_COUNT {
        return None;
    }

    let scene_node = unsafe {
        read_ptr(BSSHADERMANAGER_SHADOW_SCENE_NODE_ARRAY + scene_index * size_of::<usize>())?
    };
    if scene_node.is_null() {
        return None;
    }

    let fog_property =
        unsafe { read_ptr(scene_node as usize + SHADOW_SCENE_NODE_FOG_PROPERTY_OFFSET)? };
    if fog_property.is_null() {
        return None;
    }
    validate_memory_range(fog_property as *const c_void, BSFOGPROPERTY_SIZE).ok()?;

    let vtable = unsafe { read_ptr(fog_property as usize)? } as usize;
    if vtable != BSFOGPROPERTY_VTABLE {
        return None;
    }

    let fog_color = unsafe { read_vec3(fog_property as usize + BSFOGPROPERTY_COLOR_OFFSET)? };
    let fog_start =
        unsafe { read_f32(fog_property as usize + BSFOGPROPERTY_START_DISTANCE_OFFSET)? };
    let fog_end = unsafe { read_f32(fog_property as usize + BSFOGPROPERTY_END_DISTANCE_OFFSET)? };
    let fog_power = unsafe { read_f32(fog_property as usize + BSFOGPROPERTY_POWER_OFFSET)? };

    if !fog_color
        .iter()
        .all(|component| (-0.01..=16.0).contains(component))
        || !fog_start.is_finite()
        || !fog_end.is_finite()
        || !fog_power.is_finite()
        || fog_end <= fog_start
        || fog_end <= 0.0
    {
        return None;
    }

    Some(EnvironmentFrame {
        fog_color: fog_color.map(|component| component.max(0.0)),
        fog_start,
        fog_end,
        fog_power: fog_power.max(0.001),
        fog_available: true,
    })
}

unsafe fn read_sun_frame() -> Option<SunFrame> {
    let call = SUN_FRAME_CALLS.fetch_add(1, Ordering::Relaxed);
    let sky = unsafe { read_ptr(SKY_SINGLETON_PTR)? };
    if sky.is_null() {
        return None;
    }

    let daylight = unsafe { read_daylight_strength(sky)? };
    if daylight <= 0.001 {
        return None;
    }

    let sun = unsafe { read_ptr(sky as usize + SKY_SUN_OFFSET)? };
    if sun.is_null() {
        return None;
    }

    let sun_root = unsafe { read_ptr(sun as usize + SKY_OBJECT_ROOT_NODE_OFFSET)? };
    let camera = unsafe { read_ptr(BSSHADERMANAGER_CAMERA_PTR)? };
    if sun_root.is_null() || camera.is_null() {
        return None;
    }

    let screen = unsafe { project_sun_to_screen(sun_root, camera) };
    let Some([screen_x, screen_y, facing]) = screen else {
        if call % FRAME_CONTRACT_LOG_INTERVAL == 0
            && SUN_FRAME_LOGS.fetch_add(1, Ordering::Relaxed) < MAX_FRAME_CONTRACT_LOGS
        {
            log::info!("[FNV] Sun is behind the camera or its projection is unavailable");
        }
        return None;
    };

    if call % FRAME_CONTRACT_LOG_INTERVAL == 0
        && SUN_FRAME_LOGS.fetch_add(1, Ordering::Relaxed) < MAX_FRAME_CONTRACT_LOGS
    {
        let native_x = unsafe { read_f32(NATIVE_SUN_SCREEN_X_ADDR) }.unwrap_or(f32::NAN);
        let native_y = unsafe { read_f32(NATIVE_SUN_SCREEN_Y_ADDR) }.unwrap_or(f32::NAN);
        log::info!(
            "[FNV] Sun contract: screen=({screen_x:.5},{screen_y:.5}), facing={facing:.4}, source=nvr_direction_projection, native=({native_x:.5},{native_y:.5}), daylight={daylight:.4}"
        );
    }

    Some(SunFrame {
        screen_x,
        screen_y,
        available: true,
        daylight,
    })
}

unsafe fn read_native_sky_frame() -> Option<NativeSkyFrame> {
    let sky = unsafe { read_ptr(SKY_SINGLETON_PTR)? };
    unsafe { validate_object(sky, NATIVE_SKY_READ_SIZE)? };

    let sun = unsafe { read_prevalidated_ptr(sky, SKY_SUN_OFFSET) };
    unsafe { validate_object(sun, NATIVE_SUN_READ_SIZE)? };
    let sun_root = unsafe { read_prevalidated_ptr(sun, SKY_OBJECT_ROOT_NODE_OFFSET) };
    unsafe { validate_object(sun_root, NATIVE_SUN_ROOT_READ_SIZE)? };

    let sun_direction = normalize3(unsafe {
        read_prevalidated_vec3(sun_root, NIAVOBJECT_LOCAL_TRANSLATION_OFFSET)
    })?;
    let sky_game_hour = unsafe { read_prevalidated::<f32>(sky, SKY_GAME_HOUR_OFFSET) };
    let game_hour = if is_valid_day_hour(sky_game_hour) {
        sky_game_hour
    } else {
        unsafe { read_global_game_hour()? }
    };
    let daylight = unsafe { read_native_daylight_strength(sky, game_hour)? };
    let sky_upper = unsafe { read_prevalidated_vec3(sky, SKY_UPPER_COLOR_OFFSET) };
    let sky_lower = unsafe { read_prevalidated_vec3(sky, SKY_LOWER_COLOR_OFFSET) };
    let horizon = unsafe { read_prevalidated_vec3(sky, SKY_HORIZON_COLOR_OFFSET) };
    let sun_light = unsafe { read_prevalidated_vec3(sky, SKY_SUN_DIRECTIONAL_COLOR_OFFSET) };
    let sun_disk = unsafe { read_prevalidated_vec3(sky, SKY_SUN_DISK_COLOR_OFFSET) };
    let exterior = unsafe { read_native_player_is_exterior()? };
    let renderer = unsafe { read_ptr(NIDX9_RENDERER_SINGLETON_PTR)? };
    let z_clear = unsafe { read_f32(renderer as usize + NIDX9_RENDERER_Z_CLEAR_OFFSET)? };
    if !z_clear.is_finite() || !(0.0..=1.0).contains(&z_clear) {
        return None;
    }

    [sky_upper, sky_lower, horizon, sun_light, sun_disk]
        .into_iter()
        .flatten()
        .all(|component| component.is_finite() && (-0.01..=16.0).contains(&component))
        .then_some(NativeSkyFrame {
            sky_upper,
            sky_lower,
            horizon,
            sun_light,
            sun_disk,
            sun_direction,
            daylight: daylight.clamp(0.0, 1.0),
            game_hour,
            is_exterior: exterior,
            reversed_depth: z_clear < 1.0,
        })
}

unsafe fn validate_object(object: *mut u8, size: usize) -> Option<()> {
    if object.is_null() {
        return None;
    }
    validate_memory_range(object.cast::<c_void>(), size).ok()
}

unsafe fn read_prevalidated<T: Copy>(object: *mut u8, offset: usize) -> T {
    unsafe { object.add(offset).cast::<T>().read_unaligned() }
}

unsafe fn read_prevalidated_ptr(object: *mut u8, offset: usize) -> *mut u8 {
    unsafe { read_prevalidated::<*mut u8>(object, offset) }
}

unsafe fn read_prevalidated_vec3(object: *mut u8, offset: usize) -> [f32; 3] {
    [
        unsafe { read_prevalidated::<f32>(object, offset) },
        unsafe { read_prevalidated::<f32>(object, offset + size_of::<f32>()) },
        unsafe { read_prevalidated::<f32>(object, offset + 2 * size_of::<f32>()) },
    ]
}

unsafe fn read_native_daylight_strength(sky: *mut u8, game_hour: f32) -> Option<f32> {
    let times = unsafe { read_cached_daylight_times_contiguous() }
        .or_else(|| unsafe { read_prevalidated_climate_daylight_times(sky) })?;
    Some(times.daylight_at(game_hour))
}

unsafe fn read_cached_daylight_times_contiguous() -> Option<DaylightTimes> {
    validate_memory_range(
        CACHED_SUNRISE_BEGIN as *const c_void,
        CACHED_DAYLIGHT_TIMES_SIZE,
    )
    .ok()?;
    let base = CACHED_SUNRISE_BEGIN as *mut u8;
    DaylightTimes::new(
        unsafe { read_prevalidated::<f32>(base, 0) },
        unsafe { read_prevalidated::<f32>(base, CACHED_SUNRISE_END - CACHED_SUNRISE_BEGIN) },
        unsafe { read_prevalidated::<f32>(base, CACHED_SUNSET_BEGIN - CACHED_SUNRISE_BEGIN) },
        unsafe { read_prevalidated::<f32>(base, CACHED_SUNSET_END - CACHED_SUNRISE_BEGIN) },
    )
}

unsafe fn read_prevalidated_climate_daylight_times(sky: *mut u8) -> Option<DaylightTimes> {
    let climate = unsafe { read_prevalidated_ptr(sky, SKY_CLIMATE_OFFSET) };
    if climate.is_null() {
        return None;
    }
    validate_memory_range(
        unsafe { climate.add(CLIMATE_SUN_TIME_BYTES_OFFSET) }.cast::<c_void>(),
        CLIMATE_SUN_TIME_BYTES_LEN,
    )
    .ok()?;

    let divisor = unsafe { read_f64(SKY_SUN_TIME_DIVISOR)? } as f32;
    if !divisor.is_finite() || divisor <= 0.0 {
        return None;
    }
    DaylightTimes::new(
        unsafe { read_prevalidated::<u8>(climate, CLIMATE_SUN_TIME_BYTES_OFFSET) } as f32 / divisor,
        unsafe { read_prevalidated::<u8>(climate, CLIMATE_SUN_TIME_BYTES_OFFSET + 1) } as f32
            / divisor,
        unsafe { read_prevalidated::<u8>(climate, CLIMATE_SUN_TIME_BYTES_OFFSET + 2) } as f32
            / divisor,
        unsafe { read_prevalidated::<u8>(climate, CLIMATE_SUN_TIME_BYTES_OFFSET + 3) } as f32
            / divisor,
    )
}

unsafe fn read_native_player_is_exterior() -> Option<bool> {
    let player = unsafe { read_ptr(PLAYER_CHARACTER_PTR)? };
    unsafe { validate_object(player, NATIVE_PLAYER_READ_SIZE)? };
    let cell = unsafe { read_prevalidated_ptr(player, TESOBJECTREFR_PARENT_CELL_OFFSET) };
    unsafe { validate_object(cell, NATIVE_CELL_READ_SIZE)? };
    let flags = unsafe { read_prevalidated::<u8>(cell, TESOBJECTCELL_FLAGS0_OFFSET) };
    Some((flags & TESOBJECTCELL_FLAGS0_INTERIOR) == 0)
}

unsafe fn project_sun_to_screen(sun_root: *mut u8, camera: *mut u8) -> Option<[f32; 3]> {
    let sun_direction =
        normalize3(unsafe { read_vec3(sun_root as usize + NIAVOBJECT_LOCAL_TRANSLATION_OFFSET)? })?;
    let camera_forward =
        unsafe { read_matrix_column3(camera as usize + NIAVOBJECT_WORLD_ROTATION_OFFSET, 0)? };
    let camera_up =
        unsafe { read_matrix_column3(camera as usize + NIAVOBJECT_WORLD_ROTATION_OFFSET, 1)? };
    let camera_right =
        unsafe { read_matrix_column3(camera as usize + NIAVOBJECT_WORLD_ROTATION_OFFSET, 2)? };
    let view_x = dot3(sun_direction, camera_right);
    let view_y = dot3(sun_direction, camera_up);
    let facing = dot3(sun_direction, camera_forward);
    if !facing.is_finite() || facing <= 0.001 {
        return None;
    }

    let frustum_left = unsafe { read_f32(camera as usize + NICAMERA_FRUSTUM_LEFT_OFFSET)? };
    let frustum_right = unsafe { read_f32(camera as usize + NICAMERA_FRUSTUM_RIGHT_OFFSET)? };
    let frustum_top = unsafe { read_f32(camera as usize + NICAMERA_FRUSTUM_TOP_OFFSET)? };
    let frustum_bottom = unsafe { read_f32(camera as usize + NICAMERA_FRUSTUM_BOTTOM_OFFSET)? };
    let frustum_width = frustum_right - frustum_left;
    let frustum_height = frustum_top - frustum_bottom;
    if !frustum_width.is_finite()
        || !frustum_height.is_finite()
        || frustum_width <= f32::EPSILON
        || frustum_height <= f32::EPSILON
    {
        return None;
    }

    let ndc_x = (2.0 * view_x / facing - (frustum_right + frustum_left)) / frustum_width;
    let ndc_y = (2.0 * view_y / facing - (frustum_top + frustum_bottom)) / frustum_height;
    let screen_x = ndc_x.mul_add(0.5, 0.5);
    let screen_y = ndc_y.mul_add(-0.5, 0.5);
    if !screen_x.is_finite() || !screen_y.is_finite() {
        return None;
    }

    Some([screen_x, screen_y, facing])
}

unsafe fn read_vec3(address: usize) -> Option<[f32; 3]> {
    let value = [
        unsafe { read_f32(address)? },
        unsafe { read_f32(address + size_of::<f32>())? },
        unsafe { read_f32(address + size_of::<f32>() * 2)? },
    ];
    value
        .iter()
        .all(|component| component.is_finite())
        .then_some(value)
}

unsafe fn read_vec3_unchecked(address: usize) -> [f32; 3] {
    [
        unsafe { (address as *const f32).read() },
        unsafe { ((address + size_of::<f32>()) as *const f32).read() },
        unsafe { ((address + size_of::<f32>() * 2) as *const f32).read() },
    ]
}

unsafe fn read_matrix_column3(address: usize, column: usize) -> Option<[f32; 3]> {
    let value = [
        unsafe { read_f32(address + column * size_of::<f32>())? },
        unsafe { read_f32(address + (3 + column) * size_of::<f32>())? },
        unsafe { read_f32(address + (6 + column) * size_of::<f32>())? },
    ];
    value
        .iter()
        .all(|component| component.is_finite())
        .then_some(value)
}

fn dot3(left: [f32; 3], right: [f32; 3]) -> f32 {
    left[0].mul_add(right[0], left[1].mul_add(right[1], left[2] * right[2]))
}

fn normalize3(value: [f32; 3]) -> Option<[f32; 3]> {
    let length_squared = dot3(value, value);
    if !length_squared.is_finite() || length_squared <= f32::EPSILON {
        return None;
    }

    let inverse_length = length_squared.sqrt().recip();
    Some([
        value[0] * inverse_length,
        value[1] * inverse_length,
        value[2] * inverse_length,
    ])
}

unsafe fn read_material_state_frame() -> Option<MaterialStateFrame> {
    let exterior = unsafe { read_player_is_exterior() };

    Some(MaterialStateFrame {
        exterior_known: exterior.is_some(),
        is_exterior: exterior.unwrap_or(true),
    })
}

unsafe fn read_player_is_exterior() -> Option<bool> {
    let player = unsafe { read_ptr(PLAYER_CHARACTER_PTR)? };
    if player.is_null() {
        return None;
    }

    let cell = unsafe { read_ptr(player as usize + TESOBJECTREFR_PARENT_CELL_OFFSET)? };
    if cell.is_null() {
        return None;
    }

    if let Some(flags) = unsafe { read_u8(cell as usize + TESOBJECTCELL_FLAGS0_OFFSET) } {
        return Some((flags & TESOBJECTCELL_FLAGS0_INTERIOR) == 0);
    }

    let worldspace = unsafe { read_ptr(cell as usize + TESOBJECTCELL_WORLDSPACE_OFFSET)? };
    Some(!worldspace.is_null())
}

unsafe fn read_daylight_strength(sky: *mut u8) -> Option<f32> {
    let game_hour =
        unsafe { read_sky_game_hour(sky) }.or_else(|| unsafe { read_global_game_hour() })?;

    let times = unsafe { read_cached_daylight_times() }
        .or_else(|| unsafe { read_climate_daylight_times(sky) })?;
    Some(times.daylight_at(game_hour))
}

unsafe fn read_sky_game_hour(sky: *mut u8) -> Option<f32> {
    let game_hour = unsafe { read_f32(sky as usize + SKY_GAME_HOUR_OFFSET)? };
    is_valid_day_hour(game_hour).then_some(game_hour)
}

unsafe fn read_global_game_hour() -> Option<f32> {
    let game_hour = unsafe { read_f32(TIME_GLOBALS_BASE + TIME_GLOBALS_GAME_HOUR_OFFSET)? };
    is_valid_day_hour(game_hour).then_some(game_hour)
}

unsafe fn read_cached_daylight_times() -> Option<DaylightTimes> {
    DaylightTimes::new(
        unsafe { read_f32(CACHED_SUNRISE_BEGIN)? },
        unsafe { read_f32(CACHED_SUNRISE_END)? },
        unsafe { read_f32(CACHED_SUNSET_BEGIN)? },
        unsafe { read_f32(CACHED_SUNSET_END)? },
    )
}

unsafe fn read_climate_daylight_times(sky: *mut u8) -> Option<DaylightTimes> {
    let climate = unsafe { read_ptr(sky as usize + SKY_CLIMATE_OFFSET)? };
    if climate.is_null() {
        return None;
    }
    validate_memory_range(
        unsafe { climate.add(CLIMATE_SUN_TIME_BYTES_OFFSET) }.cast::<c_void>(),
        CLIMATE_SUN_TIME_BYTES_LEN,
    )
    .ok()?;

    let base = climate as usize + CLIMATE_SUN_TIME_BYTES_OFFSET;
    let divisor = unsafe { read_f64(SKY_SUN_TIME_DIVISOR)? } as f32;
    if !divisor.is_finite() || divisor <= 0.0 {
        return None;
    }
    DaylightTimes::new(
        unsafe { read_u8(base)? } as f32 / divisor,
        unsafe { read_u8(base + 1)? } as f32 / divisor,
        unsafe { read_u8(base + 2)? } as f32 / divisor,
        unsafe { read_u8(base + 3)? } as f32 / divisor,
    )
}

#[derive(Clone, Copy)]
struct DaylightTimes {
    sunrise_begin: f32,
    sunrise_end: f32,
    sunset_begin: f32,
    sunset_end: f32,
}

impl DaylightTimes {
    fn new(
        sunrise_begin: f32,
        sunrise_end: f32,
        sunset_begin: f32,
        sunset_end: f32,
    ) -> Option<Self> {
        let times = Self {
            sunrise_begin,
            sunrise_end,
            sunset_begin,
            sunset_end,
        };
        times.is_valid().then_some(times)
    }

    fn is_valid(self) -> bool {
        is_valid_day_hour(self.sunrise_begin)
            && is_valid_day_hour(self.sunrise_end)
            && is_valid_day_hour(self.sunset_begin)
            && is_valid_day_hour(self.sunset_end)
            && self.sunrise_begin < self.sunrise_end
            && self.sunrise_end < self.sunset_begin
            && self.sunset_begin < self.sunset_end
    }

    fn daylight_at(self, day_time: f32) -> f32 {
        if day_time < self.sunrise_begin || day_time >= self.sunset_end {
            return 0.0;
        }
        if day_time < self.sunrise_end {
            return smooth01(
                (day_time - self.sunrise_begin) / (self.sunrise_end - self.sunrise_begin),
            );
        }
        if day_time < self.sunset_begin {
            return 1.0;
        }

        1.0 - smooth01((day_time - self.sunset_begin) / (self.sunset_end - self.sunset_begin))
    }
}

fn is_valid_day_hour(value: f32) -> bool {
    value.is_finite() && (0.0..=24.1).contains(&value)
}

fn smooth01(value: f32) -> f32 {
    let value = value.clamp(0.0, 1.0);
    value * value * (3.0 - 2.0 * value)
}

fn log_depth_resolve_skip(
    slot: DepthResolveSlot,
    reason: &'static str,
    err: &FnvDepthResolveError,
) {
    if DEPTH_RESOLVE_LOGS.fetch_add(1, Ordering::AcqRel) < MAX_DEPTH_RESOLVE_LOGS {
        log::warn!(
            "[FNV] D3D depth resolve skipped: slot={}, reason={reason}, err={err}",
            slot.label()
        );
    }
}

#[derive(Default)]
struct FnvDepthResolve {
    device_ptr: usize,
    world_target: Option<FnvDepthTarget>,
    first_person_target: Option<FnvDepthTarget>,
    state_block: Option<StateBlock9>,
    success_logs: u32,
    frame_epoch: u64,
    underwater: PublishedUnderwaterClassification,
    temporal_depth_proven: bool,
    world_capture: ResolvedDepthCapture,
    first_person_capture: ResolvedDepthCapture,
}

#[derive(Clone, Copy, Debug, Default)]
struct PublishedUnderwaterClassification {
    frame_epoch: u64,
    known: bool,
    underwater: bool,
}

#[derive(Clone, Copy, Debug, Default)]
struct ResolvedDepthCapture {
    texture_ptr: usize,
    projection: DepthProjectionFrame,
    frame_epoch: u64,
    width: u32,
    height: u32,
}

impl FnvDepthResolve {
    fn publish_underwater_classification(&mut self, underwater: bool) {
        self.underwater = PublishedUnderwaterClassification {
            frame_epoch: self.frame_epoch,
            known: true,
            underwater,
        };
    }

    fn underwater_frame(&self) -> UnderwaterFrame {
        UnderwaterFrame {
            frame_epoch: self.underwater.frame_epoch,
            hook_available: crate::fnv_render::underwater_publication_hook_ready(),
            known: self.underwater.known && self.underwater.frame_epoch == self.frame_epoch,
            underwater: self.underwater.underwater,
        }
    }

    unsafe fn resolve(
        &mut self,
        device_ptr: *mut c_void,
        source_rendered_texture: Option<*mut c_void>,
        slot: DepthResolveSlot,
        reason: &'static str,
    ) -> Result<(), FnvDepthResolveError> {
        let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
            return Err(FnvDepthResolveError::Static("null D3D device"));
        };

        let (rendered_texture, source_label) = match source_rendered_texture {
            Some(rendered_texture) => (rendered_texture, "first-person render target"),
            None => {
                let rendered_texture = unsafe {
                    read_ptr_checked(
                        BSSHADERMANAGER_CURRENT_RENDER_TARGET_PTR,
                        "unreadable current render target",
                    )?
                };
                (
                    rendered_texture.cast::<c_void>(),
                    "world current render target",
                )
            }
        };
        let source_surface = unsafe { read_rendered_texture_depth_surface(rendered_texture)? };

        unsafe {
            self.resolve_from_surface(
                &device,
                device_ptr,
                source_surface,
                slot,
                reason,
                source_label,
            )
        }
    }

    unsafe fn resolve_from_surface(
        &mut self,
        device: &Device9Ref<'_>,
        device_ptr: *mut c_void,
        source_surface: *mut c_void,
        slot: DepthResolveSlot,
        reason: &'static str,
        source_label: &'static str,
    ) -> Result<(), FnvDepthResolveError> {
        if source_surface.is_null() {
            return Err(FnvDepthResolveError::Static("missing D3D depth surface"));
        }

        if self.device_ptr != 0 && self.device_ptr != device_ptr as usize {
            self.release();
        }
        self.device_ptr = device_ptr as usize;

        let desc = unsafe { Surface9::raw_desc(source_surface)? };
        if desc.Width == 0 || desc.Height == 0 {
            return Err(FnvDepthResolveError::Static("empty depth surface"));
        }
        let depth_function = device.render_state(D3DRS_ZFUNC).ok();
        let camera = match slot {
            DepthResolveSlot::World => unsafe { read_world_camera_frame(&desc) },
            DepthResolveSlot::FirstPerson => unsafe { read_camera_frame(&desc) },
        }
        .ok_or(FnvDepthResolveError::Static(match slot {
            DepthResolveSlot::World => "missing persistent world camera projection",
            DepthResolveSlot::FirstPerson => "missing first-person camera projection",
        }))?;
        let projection = DepthProjectionFrame {
            camera,
            reversed_depth: depth_convention(depth_function),
            depth_function,
            source_surface: source_surface as usize,
        };

        self.ensure_resources(device, &desc, slot)?;

        let Some(target) = self.target(slot).as_ref() else {
            return Err(FnvDepthResolveError::Static("missing INTZ target"));
        };
        let Some(state_block) = self.state_block.as_ref() else {
            return Err(FnvDepthResolveError::Static("missing D3D state block"));
        };

        state_block.capture()?;
        let states = D3dResolveStates::capture(device)?;
        let original_depth = device.depth_stencil_surface()?;

        let draw_result = (|| -> Direct3DResult<()> {
            unsafe { device.set_raw_depth_stencil_surface(source_surface)? };
            target.resolve(device)
        })();

        let restore_result = states.restore_before_resz(device);
        let resz_result = device.set_render_state(D3DRS_POINTSIZE, D3DRESZ_POINT_SIZE);
        let point_size_restore_result = device.set_render_state(D3DRS_POINTSIZE, states.point_size);
        let state_restore_result = state_block.apply();
        let depth_restore_result = device.set_depth_stencil_surface(original_depth.as_ref());

        draw_result?;
        restore_result?;
        resz_result?;
        point_size_restore_result?;
        state_restore_result?;
        depth_restore_result?;

        let texture_ptr = target.texture.as_raw_base_texture() as usize;
        *self.capture_mut(slot) = ResolvedDepthCapture {
            texture_ptr,
            projection,
            frame_epoch: self.frame_epoch,
            width: desc.Width,
            height: desc.Height,
        };
        if slot == DepthResolveSlot::World {
            self.temporal_depth_proven =
                projection.reversed_depth.is_some() && projection.camera.world_transform.available;
        }
        self.log_success(slot, reason, source_label, &desc, projection);
        Ok(())
    }

    fn ensure_resources(
        &mut self,
        device: &Device9Ref<'_>,
        desc: &D3DSURFACE_DESC,
        slot: DepthResolveSlot,
    ) -> Result<(), FnvDepthResolveError> {
        let needs_target = self
            .target(slot)
            .as_ref()
            .is_none_or(|target| !target.matches(desc));

        if needs_target {
            *self.capture_mut(slot) = ResolvedDepthCapture::default();
            if slot == DepthResolveSlot::World {
                self.temporal_depth_proven = false;
            }
            let target = FnvDepthTarget::create(device, desc)?;
            *self.target_mut(slot) = Some(target);
            log::info!(
                "[FNV] INTZ depth target: slot={}, size={}x{}",
                slot.label(),
                desc.Width,
                desc.Height
            );
        }

        if self.state_block.is_none() {
            self.state_block = Some(device.create_state_block(D3DSBT_ALL)?);
        }

        Ok(())
    }

    fn target(&self, slot: DepthResolveSlot) -> &Option<FnvDepthTarget> {
        match slot {
            DepthResolveSlot::World => &self.world_target,
            DepthResolveSlot::FirstPerson => &self.first_person_target,
        }
    }

    fn target_mut(&mut self, slot: DepthResolveSlot) -> &mut Option<FnvDepthTarget> {
        match slot {
            DepthResolveSlot::World => &mut self.world_target,
            DepthResolveSlot::FirstPerson => &mut self.first_person_target,
        }
    }

    fn capture_mut(&mut self, slot: DepthResolveSlot) -> &mut ResolvedDepthCapture {
        match slot {
            DepthResolveSlot::World => &mut self.world_capture,
            DepthResolveSlot::FirstPerson => &mut self.first_person_capture,
        }
    }

    fn invalidate_capture(&mut self, slot: DepthResolveSlot) {
        *self.capture_mut(slot) = ResolvedDepthCapture::default();
        if slot == DepthResolveSlot::World {
            self.temporal_depth_proven = false;
        }
    }

    fn temporal_depth_epoch(
        &self,
        device_ptr: *mut c_void,
        width: u32,
        height: u32,
    ) -> Option<u64> {
        (self.temporal_depth_proven
            && self.device_ptr == device_ptr as usize
            && self
                .world_target
                .as_ref()
                .is_some_and(|target| target.width == width && target.height == height))
        .then_some(self.frame_epoch)
    }

    fn depth_frame(&self) -> DepthFrame {
        let world_capture = (self.world_capture.texture_ptr != 0
            && self.world_capture.frame_epoch == self.frame_epoch)
            .then_some(self.world_capture);
        let texture =
            world_capture.and_then(|capture| DepthTexture::new(capture.texture_ptr as *mut c_void));
        let first_person_matches_world = world_capture.is_none_or(|world| {
            self.first_person_capture.width == world.width
                && self.first_person_capture.height == world.height
        });
        let first_person_capture = (self.first_person_capture.texture_ptr != 0
            && self.first_person_capture.frame_epoch == self.frame_epoch
            && first_person_matches_world)
            .then_some(self.first_person_capture);
        let first_person_texture = first_person_capture
            .and_then(|capture| DepthTexture::new(capture.texture_ptr as *mut c_void));
        let first_person_projection = first_person_texture
            .and_then(|_| first_person_capture.map(|capture| capture.projection))
            .unwrap_or_default();

        DepthFrame::from_textures(
            DepthProvider::FalloutNewVegas,
            texture,
            first_person_texture,
            texture
                .and_then(|_| world_capture.map(|capture| capture.projection))
                .unwrap_or_default(),
            first_person_projection,
            self.frame_epoch,
        )
    }

    fn finish_frame(&mut self) {
        self.frame_epoch = self.frame_epoch.wrapping_add(1);
        self.world_capture = ResolvedDepthCapture::default();
        self.first_person_capture = ResolvedDepthCapture::default();
    }

    fn log_success(
        &mut self,
        slot: DepthResolveSlot,
        reason: &'static str,
        source_label: &'static str,
        desc: &D3DSURFACE_DESC,
        projection: DepthProjectionFrame,
    ) {
        let log_index = self.success_logs;
        self.success_logs = self.success_logs.saturating_add(1);
        if log_index % FRAME_CONTRACT_LOG_INTERVAL < 2
            && log_index / FRAME_CONTRACT_LOG_INTERVAL < MAX_FRAME_CONTRACT_LOGS
        {
            log::info!(
                "[FNV] Depth contract: slot={}, source={source_label}, reason={reason}, surface=0x{:08X}, size={}x{}, zfunc={:?}, reversed={:?}, near={:.4}, far={:.2}, frustum=({:.5},{:.5},{:.5},{:.5}), transform={}, position=({:.2},{:.2},{:.2}), scale={:.4}",
                slot.label(),
                projection.source_surface,
                desc.Width,
                desc.Height,
                projection.depth_function,
                projection.reversed_depth,
                projection.camera.near_z,
                projection.camera.far_z,
                projection.camera.frustum_left,
                projection.camera.frustum_right,
                projection.camera.frustum_bottom,
                projection.camera.frustum_top,
                projection.camera.world_transform.available,
                projection.camera.world_transform.translation[0],
                projection.camera.world_transform.translation[1],
                projection.camera.world_transform.translation[2],
                projection.camera.world_transform.scale,
            );
        }
    }

    fn release(&mut self) {
        self.device_ptr = 0;
        self.temporal_depth_proven = false;
        self.world_target = None;
        self.first_person_target = None;
        self.state_block = None;
        self.underwater = PublishedUnderwaterClassification::default();
        self.finish_frame();
    }
}

#[cfg(test)]
mod depth_capture_tests {
    use super::{DepthProjectionFrame, FnvDepthResolve, ResolvedDepthCapture};

    fn capture(
        texture_ptr: usize,
        frame_epoch: u64,
        width: u32,
        height: u32,
    ) -> ResolvedDepthCapture {
        ResolvedDepthCapture {
            texture_ptr,
            projection: DepthProjectionFrame {
                source_surface: texture_ptr,
                ..DepthProjectionFrame::default()
            },
            frame_epoch,
            width,
            height,
        }
    }

    #[test]
    fn first_person_capture_requires_matching_epoch_and_size() {
        let mut resolve = FnvDepthResolve {
            frame_epoch: 7,
            world_capture: capture(1, 7, 1920, 1080),
            first_person_capture: capture(2, 6, 1920, 1080),
            ..FnvDepthResolve::default()
        };

        assert!(resolve.depth_frame().first_person_texture.is_none());

        resolve.first_person_capture = capture(2, 7, 1280, 720);
        assert!(resolve.depth_frame().first_person_texture.is_none());

        resolve.first_person_capture = capture(2, 7, 1920, 1080);
        let frame = resolve.depth_frame();
        assert!(frame.first_person_texture.is_some());
        assert_eq!(frame.first_person_projection.source_surface, 2);
        assert_eq!(frame.capture_epoch, 7);
    }

    #[test]
    fn first_person_capture_is_available_without_world_capture() {
        let resolve = FnvDepthResolve {
            frame_epoch: 7,
            first_person_capture: capture(2, 7, 1920, 1080),
            ..FnvDepthResolve::default()
        };

        let frame = resolve.depth_frame();
        assert!(frame.texture.is_none());
        assert!(frame.first_person_texture.is_some());
        assert_eq!(frame.first_person_projection.source_surface, 2);
        assert_eq!(frame.capture_epoch, 7);
    }

    #[test]
    fn finishing_frame_invalidates_both_captures() {
        let mut resolve = FnvDepthResolve {
            frame_epoch: 7,
            world_capture: capture(1, 7, 1920, 1080),
            first_person_capture: capture(2, 7, 1920, 1080),
            ..FnvDepthResolve::default()
        };

        resolve.finish_frame();

        assert_eq!(resolve.frame_epoch, 8);
        assert!(!resolve.depth_frame().is_available());
    }

    #[test]
    fn underwater_classification_requires_the_current_epoch() {
        let mut resolve = FnvDepthResolve {
            frame_epoch: 7,
            ..FnvDepthResolve::default()
        };

        resolve.publish_underwater_classification(true);
        let current = resolve.underwater_frame();
        assert!(current.known);
        assert!(current.underwater);
        assert_eq!(current.frame_epoch, 7);

        resolve.finish_frame();
        let stale = resolve.underwater_frame();
        assert!(!stale.known);
        assert_eq!(stale.frame_epoch, 7);
    }

    #[test]
    fn fallback_above_water_value_is_published_without_an_engine_pointer() {
        let mut resolve = FnvDepthResolve {
            frame_epoch: 11,
            ..FnvDepthResolve::default()
        };

        resolve.publish_underwater_classification(false);
        let frame = resolve.underwater_frame();
        assert!(frame.known);
        assert!(!frame.underwater);
        assert_eq!(frame.frame_epoch, 11);
    }
}

fn depth_convention(depth_function: Option<u32>) -> Option<bool> {
    match depth_function? {
        5 | 7 => Some(true),
        2 | 4 => Some(false),
        _ => None,
    }
}

struct FnvDepthTarget {
    width: u32,
    height: u32,
    texture: Texture9,
}

impl FnvDepthTarget {
    fn create(
        device: &Device9Ref<'_>,
        desc: &D3DSURFACE_DESC,
    ) -> Result<Self, FnvDepthResolveError> {
        device.direct3d()?.check_default_resz_support()?;
        let texture = device.create_depth_stencil_texture(desc.Width, desc.Height, D3DFMT_INTZ)?;

        Ok(Self {
            width: desc.Width,
            height: desc.Height,
            texture,
        })
    }

    fn matches(&self, desc: &D3DSURFACE_DESC) -> bool {
        self.width == desc.Width && self.height == desc.Height
    }

    fn resolve(&self, device: &Device9Ref<'_>) -> Direct3DResult<()> {
        device.set_texture(0, &self.texture)?;
        device.clear_vertex_shader()?;
        device.clear_pixel_shader()?;
        device.set_fvf(PositionVertex::FVF)?;
        device.set_render_state(D3DRS_CULLMODE, D3DCULL_NONE.0 as u32)?;
        device.set_render_state(D3DRS_ALPHABLENDENABLE, 0)?;
        device.set_render_state(D3DRS_ALPHATESTENABLE, 0)?;
        device.set_render_state(D3DRS_ZENABLE, 0)?;
        device.set_render_state(D3DRS_ZWRITEENABLE, 0)?;
        device.set_render_state(D3DRS_COLORWRITEENABLE, 0)?;

        let point = [PositionVertex::origin()];
        unsafe {
            device.draw_primitive_up(D3DPT_POINTLIST, 1, &point)?;
        }

        Ok(())
    }
}

#[derive(Clone, Copy)]
struct D3dResolveStates {
    cull: u32,
    alpha_blend: u32,
    z_enable: u32,
    z_write: u32,
    color_write: u32,
    point_size: u32,
}

impl D3dResolveStates {
    fn capture(device: &Device9Ref<'_>) -> Direct3DResult<Self> {
        Ok(Self {
            cull: device.render_state(D3DRS_CULLMODE)?,
            alpha_blend: device.render_state(D3DRS_ALPHABLENDENABLE)?,
            z_enable: device.render_state(D3DRS_ZENABLE)?,
            z_write: device.render_state(D3DRS_ZWRITEENABLE)?,
            color_write: device.render_state(D3DRS_COLORWRITEENABLE)?,
            point_size: device.render_state(D3DRS_POINTSIZE)?,
        })
    }

    fn restore_before_resz(self, device: &Device9Ref<'_>) -> Direct3DResult<()> {
        device.set_render_state(D3DRS_COLORWRITEENABLE, self.color_write)?;
        device.set_render_state(D3DRS_ZWRITEENABLE, self.z_write)?;
        device.set_render_state(D3DRS_ZENABLE, self.z_enable)?;
        device.set_render_state(D3DRS_ALPHABLENDENABLE, self.alpha_blend)?;
        device.set_render_state(D3DRS_CULLMODE, self.cull)?;
        Ok(())
    }
}

#[derive(Debug)]
enum FnvDepthResolveError {
    Static(&'static str),
    D3d(WindowsError),
}

impl fmt::Display for FnvDepthResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static(message) => f.write_str(message),
            Self::D3d(err) => write!(f, "{err}"),
        }
    }
}

impl From<WindowsError> for FnvDepthResolveError {
    fn from(value: WindowsError) -> Self {
        Self::D3d(value)
    }
}

impl From<&'static str> for FnvDepthResolveError {
    fn from(value: &'static str) -> Self {
        Self::Static(value)
    }
}

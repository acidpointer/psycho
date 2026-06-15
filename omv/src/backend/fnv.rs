//! Fallout New Vegas backend.

use core::{ffi::c_void, fmt, mem::size_of};
use std::sync::{
    LazyLock,
    atomic::{AtomicU32, AtomicUsize, Ordering},
};

use libpsycho::os::windows::{
    directx9::{
        D3DCULL_NONE, D3DFMT_INTZ, D3DPT_POINTLIST, D3DRESZ_POINT_SIZE, D3DRS_ALPHABLENDENABLE,
        D3DRS_COLORWRITEENABLE, D3DRS_CULLMODE, D3DRS_POINTSIZE, D3DRS_ZENABLE, D3DRS_ZWRITEENABLE,
        D3DSBT_ALL, Device9Ref, Direct3DResult, PositionVertex, StateBlock9, Surface9, Texture9,
    },
    memory::validate_memory_range,
};
use parking_lot::Mutex;
use windows::Win32::Graphics::Direct3D9::D3DSURFACE_DESC;
use windows::core::Error as WindowsError;

use super::{CameraFrame, DepthResolveSlot, EnvironmentFrame, SunFrame};

const NIDX9_RENDERER_SINGLETON_PTR: usize = 0x011C73B4;
const NIDX9_RENDERER_DEVICE_OFFSET: usize = 0x288;
const BSSHADERMANAGER_CAMERA_PTR: usize = 0x011F917C;
const BSSHADERMANAGER_SCENE_GRAPH_INDEX: usize = 0x011F91C4;
const BSSHADERMANAGER_SHADOW_SCENE_NODE_ARRAY: usize = 0x011F91C8;
const BSSHADERMANAGER_SHADOW_SCENE_NODE_COUNT: usize = 4;
const SKY_SINGLETON_PTR: usize = 0x011DEA20;
const TIME_GLOBALS_BASE: usize = 0x011DE7B8;
const TIME_GLOBALS_GAME_HOUR_OFFSET: usize = 0x0C;
const SKY_CLIMATE_OFFSET: usize = 0x0C;
const SKY_SUN_OFFSET: usize = 0x28;
const SKY_GAME_HOUR_OFFSET: usize = 0xEC;
const SKYOBJECT_ROOT_NODE_OFFSET: usize = 0x04;
const CLIMATE_SUN_TIME_BYTES_OFFSET: usize = 0x50;
const CLIMATE_SUN_TIME_BYTES_LEN: usize = 4;
const CACHED_SUNRISE_BEGIN: usize = 0x011CA9E8;
const CACHED_SUNRISE_END: usize = 0x011CA9EC;
const CACHED_SUNSET_BEGIN: usize = 0x011CA9F0;
const CACHED_SUNSET_END: usize = 0x011CA9F4;
const SKY_SUN_TIME_DIVISOR: usize = 0x01034208;

const NIAVOBJECT_WORLD_ROT_FORWARD_X_OFFSET: usize = 0x68;
const NIAVOBJECT_WORLD_ROT_FORWARD_Y_OFFSET: usize = 0x74;
const NIAVOBJECT_WORLD_ROT_FORWARD_Z_OFFSET: usize = 0x80;
const NIAVOBJECT_WORLD_ROT_UP_X_OFFSET: usize = 0x6C;
const NIAVOBJECT_WORLD_ROT_UP_Y_OFFSET: usize = 0x78;
const NIAVOBJECT_WORLD_ROT_UP_Z_OFFSET: usize = 0x84;
const NIAVOBJECT_WORLD_ROT_RIGHT_X_OFFSET: usize = 0x70;
const NIAVOBJECT_WORLD_ROT_RIGHT_Y_OFFSET: usize = 0x7C;
const NIAVOBJECT_WORLD_ROT_RIGHT_Z_OFFSET: usize = 0x88;
const NIAVOBJECT_WORLD_POS_OFFSET: usize = 0x8C;
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
const NI2DBUFFER_SIZE: usize = 0x14;
const NI2DBUFFER_RENDERER_DATA_OFFSET: usize = 0x10;
const NIDX9_TEXTURE_BUFFER_DATA_SURFACE_OFFSET: usize = 0x14;
const SHADOW_SCENE_NODE_FOG_PROPERTY_OFFSET: usize = 0x134;
const BSFOGPROPERTY_VTABLE: usize = 0x010B9E38;
const BSFOGPROPERTY_SIZE: usize = 0x64;
const BSFOGPROPERTY_START_DISTANCE_OFFSET: usize = 0x2C;
const BSFOGPROPERTY_END_DISTANCE_OFFSET: usize = 0x30;
const BSFOGPROPERTY_POWER_OFFSET: usize = 0x60;
const MAX_DEPTH_RESOLVE_LOGS: u32 = 16;

static DEPTH_RESOLVE_LOGS: AtomicU32 = AtomicU32::new(0);
static RESOLVED_WORLD_DEPTH_TEXTURE: AtomicUsize = AtomicUsize::new(0);
static RESOLVED_FIRST_PERSON_DEPTH_TEXTURE: AtomicUsize = AtomicUsize::new(0);
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
    let fallback = CameraFrame::fallback(desc);

    unsafe {
        let Some(camera) = read_ptr(BSSHADERMANAGER_CAMERA_PTR) else {
            return fallback;
        };
        if camera.is_null() {
            return fallback;
        }

        let near_z = match read_f32(camera as usize + NICAMERA_FRUSTUM_NEAR_OFFSET) {
            Some(value) => value,
            None => 0.0,
        };
        let far_z = match read_f32(camera as usize + NICAMERA_FRUSTUM_FAR_OFFSET) {
            Some(value) => value,
            None => 0.0,
        };
        if !near_z.is_finite() || !far_z.is_finite() || near_z <= 0.0 || far_z <= near_z {
            return fallback;
        }

        CameraFrame {
            near_z,
            far_z,
            aspect_ratio: fallback.aspect_ratio,
        }
    }
}

pub(super) fn environment_frame() -> EnvironmentFrame {
    unsafe { read_environment_frame().unwrap_or_default() }
}

pub(super) fn sun_frame() -> SunFrame {
    unsafe { read_sun_frame().unwrap_or_default() }
}

pub(super) fn depth_texture_ptr() -> Option<*mut c_void> {
    let ptr = RESOLVED_WORLD_DEPTH_TEXTURE.load(Ordering::Acquire);
    (ptr != 0).then_some(ptr as *mut c_void)
}

pub(super) fn first_person_depth_texture_ptr() -> Option<*mut c_void> {
    let ptr = RESOLVED_FIRST_PERSON_DEPTH_TEXTURE.load(Ordering::Acquire);
    (ptr != 0).then_some(ptr as *mut c_void)
}

pub(super) fn rendered_texture_color_surface(rendered_texture: *mut c_void) -> Option<*mut c_void> {
    unsafe { read_rendered_texture_color_surface(rendered_texture).ok() }
}

pub(super) unsafe fn resolve_scene_depth(
    device_ptr: *mut c_void,
    slot: DepthResolveSlot,
    reason: &'static str,
) -> bool {
    match unsafe { DEPTH_RESOLVE.lock().resolve(device_ptr, slot, reason) } {
        Ok(()) => true,
        Err(err) => {
            log_depth_resolve_skip(slot, reason, &err);
            false
        }
    }
}

pub(super) fn finish_frame() {
    RESOLVED_WORLD_DEPTH_TEXTURE.store(0, Ordering::Release);
    RESOLVED_FIRST_PERSON_DEPTH_TEXTURE.store(0, Ordering::Release);
}

pub(super) fn reset_depth_resources() {
    RESOLVED_WORLD_DEPTH_TEXTURE.store(0, Ordering::Release);
    RESOLVED_FIRST_PERSON_DEPTH_TEXTURE.store(0, Ordering::Release);
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

unsafe fn read_vec3(address: usize) -> Option<Vec3> {
    Some(Vec3 {
        x: unsafe { read_f32(address)? },
        y: unsafe { read_f32(address + size_of::<f32>())? },
        z: unsafe { read_f32(address + size_of::<f32>() * 2)? },
    })
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

    let fog_start =
        unsafe { read_f32(fog_property as usize + BSFOGPROPERTY_START_DISTANCE_OFFSET)? };
    let fog_end = unsafe { read_f32(fog_property as usize + BSFOGPROPERTY_END_DISTANCE_OFFSET)? };
    let fog_power = unsafe { read_f32(fog_property as usize + BSFOGPROPERTY_POWER_OFFSET)? };

    if !fog_start.is_finite()
        || !fog_end.is_finite()
        || !fog_power.is_finite()
        || fog_end <= fog_start
        || fog_end <= 0.0
    {
        return None;
    }

    Some(EnvironmentFrame {
        fog_start,
        fog_end,
        fog_power: fog_power.max(0.001),
        fog_available: true,
    })
}

unsafe fn read_sun_frame() -> Option<SunFrame> {
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

    let sun_root = unsafe { read_ptr(sun as usize + SKYOBJECT_ROOT_NODE_OFFSET)? };
    if sun_root.is_null() {
        return None;
    }

    let sun_position = unsafe { read_vec3(sun_root as usize + NIAVOBJECT_WORLD_POS_OFFSET)? };
    if !sun_position.is_valid() {
        return None;
    }

    let camera = unsafe { read_ptr(BSSHADERMANAGER_CAMERA_PTR)? };
    if camera.is_null() {
        return None;
    }

    let camera_position = unsafe { read_vec3(camera as usize + NIAVOBJECT_WORLD_POS_OFFSET)? };
    let forward = Vec3 {
        x: unsafe { read_f32(camera as usize + NIAVOBJECT_WORLD_ROT_FORWARD_X_OFFSET)? },
        y: unsafe { read_f32(camera as usize + NIAVOBJECT_WORLD_ROT_FORWARD_Y_OFFSET)? },
        z: unsafe { read_f32(camera as usize + NIAVOBJECT_WORLD_ROT_FORWARD_Z_OFFSET)? },
    }
    .normalized()?;
    let up = Vec3 {
        x: unsafe { read_f32(camera as usize + NIAVOBJECT_WORLD_ROT_UP_X_OFFSET)? },
        y: unsafe { read_f32(camera as usize + NIAVOBJECT_WORLD_ROT_UP_Y_OFFSET)? },
        z: unsafe { read_f32(camera as usize + NIAVOBJECT_WORLD_ROT_UP_Z_OFFSET)? },
    }
    .normalized()?;
    let right = Vec3 {
        x: unsafe { read_f32(camera as usize + NIAVOBJECT_WORLD_ROT_RIGHT_X_OFFSET)? },
        y: unsafe { read_f32(camera as usize + NIAVOBJECT_WORLD_ROT_RIGHT_Y_OFFSET)? },
        z: unsafe { read_f32(camera as usize + NIAVOBJECT_WORLD_ROT_RIGHT_Z_OFFSET)? },
    }
    .normalized()?;

    let left = unsafe { read_f32(camera as usize + NICAMERA_FRUSTUM_LEFT_OFFSET)? };
    let frustum_right = unsafe { read_f32(camera as usize + NICAMERA_FRUSTUM_RIGHT_OFFSET)? };
    let top = unsafe { read_f32(camera as usize + NICAMERA_FRUSTUM_TOP_OFFSET)? };
    let bottom = unsafe { read_f32(camera as usize + NICAMERA_FRUSTUM_BOTTOM_OFFSET)? };
    if !left.is_finite()
        || !frustum_right.is_finite()
        || !top.is_finite()
        || !bottom.is_finite()
        || frustum_right <= left
        || top <= bottom
    {
        return None;
    }

    let to_sun = sun_position.sub(camera_position);
    let view_x = to_sun.dot(right);
    let view_y = to_sun.dot(up);
    let view_z = to_sun.dot(forward);
    if !view_x.is_finite() || !view_y.is_finite() || !view_z.is_finite() || view_z <= 0.001 {
        return None;
    }

    let frustum_width = frustum_right - left;
    let frustum_height = top - bottom;
    let ndc_x = ((2.0 * view_x / view_z) - (frustum_right + left)) / frustum_width;
    let ndc_y = ((2.0 * view_y / view_z) - (top + bottom)) / frustum_height;
    let screen_x = ndc_x * 0.5 + 0.5;
    let screen_y = 0.5 - ndc_y * 0.5;
    if !screen_x.is_finite() || !screen_y.is_finite() {
        return None;
    }

    Some(SunFrame {
        screen_x,
        screen_y,
        available: true,
        daylight,
    })
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

#[derive(Clone, Copy)]
struct Vec3 {
    x: f32,
    y: f32,
    z: f32,
}

impl Vec3 {
    fn is_valid(self) -> bool {
        self.x.is_finite() && self.y.is_finite() && self.z.is_finite()
    }

    fn dot(self, other: Self) -> f32 {
        self.x * other.x + self.y * other.y + self.z * other.z
    }

    fn sub(self, other: Self) -> Self {
        Self {
            x: self.x - other.x,
            y: self.y - other.y,
            z: self.z - other.z,
        }
    }

    fn normalized(self) -> Option<Self> {
        if !self.is_valid() {
            return None;
        }

        let len_sq = self.dot(self);
        if !len_sq.is_finite() || len_sq <= 0.000001 {
            return None;
        }

        let inv_len = len_sq.sqrt().recip();
        Some(Self {
            x: self.x * inv_len,
            y: self.y * inv_len,
            z: self.z * inv_len,
        })
    }
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
}

impl FnvDepthResolve {
    unsafe fn resolve(
        &mut self,
        device_ptr: *mut c_void,
        slot: DepthResolveSlot,
        reason: &'static str,
    ) -> Result<(), FnvDepthResolveError> {
        let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
            return Err(FnvDepthResolveError::Static("null D3D device"));
        };

        let source_surface = device.depth_stencil_surface()?;
        let Some(source_surface) = source_surface.as_ref() else {
            return Err(FnvDepthResolveError::Static(
                "missing active D3D depth surface",
            ));
        };

        unsafe {
            self.resolve_from_surface(
                &device,
                device_ptr,
                source_surface.as_raw(),
                slot,
                reason,
                "active D3D",
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
        match slot {
            DepthResolveSlot::World => {
                RESOLVED_WORLD_DEPTH_TEXTURE.store(texture_ptr, Ordering::Release);
            }
            DepthResolveSlot::FirstPerson => {
                RESOLVED_FIRST_PERSON_DEPTH_TEXTURE.store(texture_ptr, Ordering::Release);
            }
        }
        self.log_success(slot, reason, source_label, &desc);
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
            *self.target_mut(slot) = Some(FnvDepthTarget::create(device, desc)?);
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

    fn log_success(
        &mut self,
        slot: DepthResolveSlot,
        reason: &'static str,
        source_label: &'static str,
        desc: &D3DSURFACE_DESC,
    ) {
        if self.success_logs < 8 {
            log::debug!(
                "[FNV] D3D depth resolved: slot={}, source={source_label}, reason={reason}, size={}x{}",
                slot.label(),
                desc.Width,
                desc.Height
            );
            self.success_logs += 1;
        }
    }

    fn release(&mut self) {
        self.device_ptr = 0;
        self.world_target = None;
        self.first_person_target = None;
        self.state_block = None;
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

//! Active game backend for the portable D3D9 renderer.

use core::ffi::c_void;

use libpsycho::os::windows::directx9::D3DSURFACE_DESC;

use crate::config::DepthProviderConfig;

mod fnv;

pub(crate) use fnv::WorldCameraJitter;

pub(crate) fn d3d_device_ptr() -> Option<*mut c_void> {
    fnv::d3d_device_ptr()
}

pub(crate) fn startup_log(depth_provider: DepthProvider) {
    log::info!("[BACKEND] Active backend: Fallout New Vegas");
    log::info!("[BACKEND] Depth provider: {}", depth_provider.label());
}

pub(crate) fn camera_frame(depth_provider: DepthProvider, desc: &D3DSURFACE_DESC) -> CameraFrame {
    match depth_provider {
        DepthProvider::None => CameraFrame::fallback(desc),
        DepthProvider::FalloutNewVegas => fnv::camera_frame(desc),
    }
}

pub(crate) fn environment_frame(depth_provider: DepthProvider) -> EnvironmentFrame {
    match depth_provider {
        DepthProvider::None => EnvironmentFrame::default(),
        DepthProvider::FalloutNewVegas => fnv::environment_frame(),
    }
}

pub(crate) fn sun_frame(depth_provider: DepthProvider) -> SunFrame {
    match depth_provider {
        DepthProvider::None => SunFrame::default(),
        DepthProvider::FalloutNewVegas => fnv::sun_frame(),
    }
}

pub(crate) fn material_state_frame() -> MaterialStateFrame {
    fnv::material_state_frame()
}

pub(crate) fn native_sky_frame() -> Option<NativeSkyFrame> {
    fnv::native_sky_frame()
}

pub(crate) fn depth_frame(depth_provider: DepthProvider) -> DepthFrame {
    match depth_provider {
        DepthProvider::None => DepthFrame::none(),
        DepthProvider::FalloutNewVegas => fnv::depth_frame(),
    }
}

pub(crate) fn fnv_temporal_depth_epoch(
    device_ptr: *mut c_void,
    width: u32,
    height: u32,
) -> Option<u64> {
    fnv::temporal_depth_epoch(device_ptr, width, height)
}

pub(crate) fn fnv_world_camera_frame(width: u32, height: u32) -> Option<CameraFrame> {
    fnv::world_camera_frame(width, height)
}

pub(crate) unsafe fn jitter_fnv_world_camera(
    jitter_pixels: [f32; 2],
    width: u32,
    height: u32,
) -> Option<WorldCameraJitter> {
    unsafe { fnv::jitter_world_camera(jitter_pixels, width, height) }
}

pub(crate) fn rendered_texture_color_surface(
    depth_provider: DepthProvider,
    rendered_texture: *mut c_void,
) -> Option<*mut c_void> {
    match depth_provider {
        DepthProvider::None => None,
        DepthProvider::FalloutNewVegas => fnv::rendered_texture_color_surface(rendered_texture),
    }
}

pub(crate) unsafe fn resolve_scene_depth(
    depth_provider: DepthProvider,
    device_ptr: *mut c_void,
    source_rendered_texture: Option<*mut c_void>,
    slot: DepthResolveSlot,
    reason: &'static str,
) -> bool {
    match depth_provider {
        DepthProvider::None => false,
        DepthProvider::FalloutNewVegas => unsafe {
            fnv::resolve_scene_depth(device_ptr, source_rendered_texture, slot, reason)
        },
    }
}

pub(crate) fn finish_frame() {
    fnv::finish_frame();
}

pub(crate) fn reset_depth_resources() {
    fnv::reset_depth_resources();
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum DepthProvider {
    #[default]
    None,
    FalloutNewVegas,
}

impl DepthProvider {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::FalloutNewVegas => "fallout_new_vegas",
        }
    }
}

impl From<DepthProviderConfig> for DepthProvider {
    fn from(value: DepthProviderConfig) -> Self {
        match value {
            DepthProviderConfig::None => Self::None,
            DepthProviderConfig::FalloutNewVegas => Self::FalloutNewVegas,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DepthResolveSlot {
    World,
    FirstPerson,
}

impl DepthResolveSlot {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::World => "world",
            Self::FirstPerson => "first_person",
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct FrameInputs {
    pub(crate) camera: CameraFrame,
    pub(crate) depth: DepthFrame,
    pub(crate) environment: EnvironmentFrame,
    pub(crate) sun: SunFrame,
    pub(crate) material_state: MaterialStateFrame,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DepthFrame {
    pub(crate) provider: DepthProvider,
    pub(crate) texture: Option<DepthTexture>,
    pub(crate) first_person_texture: Option<DepthTexture>,
    pub(crate) world_projection: DepthProjectionFrame,
    pub(crate) first_person_projection: DepthProjectionFrame,
    pub(crate) capture_epoch: u64,
}

impl DepthFrame {
    pub(crate) fn none() -> Self {
        Self {
            provider: DepthProvider::None,
            texture: None,
            first_person_texture: None,
            world_projection: DepthProjectionFrame::default(),
            first_person_projection: DepthProjectionFrame::default(),
            capture_epoch: 0,
        }
    }

    pub(crate) fn from_textures(
        provider: DepthProvider,
        texture: DepthTexture,
        first_person_texture: Option<DepthTexture>,
        world_projection: DepthProjectionFrame,
        first_person_projection: DepthProjectionFrame,
        capture_epoch: u64,
    ) -> Self {
        Self {
            provider,
            texture: Some(texture),
            first_person_texture,
            world_projection,
            first_person_projection,
            capture_epoch,
        }
    }

    pub(crate) fn is_available(self) -> bool {
        self.texture.is_some()
    }

    pub(crate) fn provider_id(self) -> f32 {
        match self.provider {
            DepthProvider::None => 0.0,
            DepthProvider::FalloutNewVegas => 2.0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DepthTexture {
    ptr: *mut c_void,
}

impl DepthTexture {
    pub(crate) fn new(ptr: *mut c_void) -> Option<Self> {
        (!ptr.is_null()).then_some(Self { ptr })
    }

    pub(crate) fn as_ptr(self) -> *mut c_void {
        self.ptr
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CameraFrame {
    pub(crate) near_z: f32,
    pub(crate) far_z: f32,
    pub(crate) aspect_ratio: f32,
    pub(crate) frustum_left: f32,
    pub(crate) frustum_right: f32,
    pub(crate) frustum_bottom: f32,
    pub(crate) frustum_top: f32,
    pub(crate) world_transform: CameraTransformFrame,
    pub(crate) available: bool,
}

impl CameraFrame {
    pub(crate) fn fallback(desc: &D3DSURFACE_DESC) -> Self {
        let aspect_ratio = if desc.Height > 0 {
            desc.Width as f32 / desc.Height as f32
        } else {
            1.0
        };

        Self {
            near_z: 0.0,
            far_z: 0.0,
            aspect_ratio,
            frustum_left: 0.0,
            frustum_right: 0.0,
            frustum_bottom: 0.0,
            frustum_top: 0.0,
            world_transform: CameraTransformFrame::default(),
            available: false,
        }
    }

    pub(crate) fn available_f32(self) -> f32 {
        if self.available { 1.0 } else { 0.0 }
    }
}

impl Default for CameraFrame {
    fn default() -> Self {
        Self {
            near_z: 0.0,
            far_z: 0.0,
            aspect_ratio: 1.0,
            frustum_left: 0.0,
            frustum_right: 0.0,
            frustum_bottom: 0.0,
            frustum_top: 0.0,
            world_transform: CameraTransformFrame::default(),
            available: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CameraTransformFrame {
    pub(crate) rotation: [[f32; 3]; 3],
    pub(crate) translation: [f32; 3],
    pub(crate) scale: f32,
    pub(crate) available: bool,
}

impl Default for CameraTransformFrame {
    fn default() -> Self {
        Self {
            rotation: [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
            translation: [0.0; 3],
            scale: 1.0,
            available: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DepthProjectionFrame {
    pub(crate) camera: CameraFrame,
    pub(crate) reversed_depth: Option<bool>,
    pub(crate) depth_function: Option<u32>,
    pub(crate) source_surface: usize,
}

impl DepthProjectionFrame {
    pub(crate) fn reversed_depth_f32(self) -> f32 {
        match self.reversed_depth {
            Some(true) => 1.0,
            Some(false) => 0.0,
            None => -1.0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct EnvironmentFrame {
    pub(crate) fog_start: f32,
    pub(crate) fog_end: f32,
    pub(crate) fog_power: f32,
    pub(crate) fog_available: bool,
}

impl EnvironmentFrame {
    pub(crate) fn fog_available_f32(self) -> f32 {
        if self.fog_available { 1.0 } else { 0.0 }
    }
}

impl Default for EnvironmentFrame {
    fn default() -> Self {
        Self {
            fog_start: 0.0,
            fog_end: 0.0,
            fog_power: 1.0,
            fog_available: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SunFrame {
    pub(crate) screen_x: f32,
    pub(crate) screen_y: f32,
    pub(crate) available: bool,
    pub(crate) daylight: f32,
}

impl SunFrame {
    pub(crate) fn available_f32(self) -> f32 {
        if self.available { 1.0 } else { 0.0 }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct MaterialStateFrame {
    pub(crate) exterior_known: bool,
    pub(crate) is_exterior: bool,
}

impl Default for MaterialStateFrame {
    fn default() -> Self {
        Self {
            exterior_known: false,
            is_exterior: true,
        }
    }
}

impl Default for SunFrame {
    fn default() -> Self {
        Self {
            screen_x: 0.5,
            screen_y: 0.18,
            available: false,
            daylight: 0.0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeSkyFrame {
    pub(crate) sky_upper: [f32; 3],
    pub(crate) sky_lower: [f32; 3],
    pub(crate) horizon: [f32; 3],
    pub(crate) sun_light: [f32; 3],
    pub(crate) sun_disk: [f32; 3],
    pub(crate) sun_direction: [f32; 3],
    pub(crate) daylight: f32,
    pub(crate) game_hour: f32,
    pub(crate) is_exterior: bool,
    pub(crate) reversed_depth: bool,
}

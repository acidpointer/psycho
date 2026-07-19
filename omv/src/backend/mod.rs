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

pub(crate) fn atmosphere_frame_from_depth(
    depth_provider: DepthProvider,
    desc: &D3DSURFACE_DESC,
    user_max_distance: f32,
    depth: DepthFrame,
    underwater: UnderwaterFrame,
) -> AtmosphereFrame {
    let camera = if depth.world_projection.camera.available {
        depth.world_projection.camera
    } else {
        camera_frame(depth_provider, desc)
    };
    let environment = environment_frame(depth_provider);
    let material_state = material_state_frame();
    let mut distance_bound = if user_max_distance.is_finite() {
        user_max_distance.max(camera.near_z + 1.0)
    } else {
        camera.near_z + 1.0
    };
    if camera.available {
        distance_bound = distance_bound.min(camera.far_z);
    }
    if environment.fog_available {
        distance_bound = distance_bound.min(environment.fog_end.max(camera.near_z + 1.0));
    }

    AtmosphereFrame {
        camera,
        depth,
        environment,
        underwater,
        sun: sun_frame(depth_provider),
        sky: native_sky_frame(),
        material_state,
        frame_epoch: depth.capture_epoch,
        distance_bound,
    }
}

pub(crate) fn publish_fnv_underwater_classification(underwater: bool) {
    fnv::publish_underwater_classification(underwater);
}

pub(crate) fn publish_fnv_first_person_rendered() {
    fnv::publish_first_person_rendered();
}

pub(crate) fn fnv_first_person_rendered() -> bool {
    fnv::first_person_rendered()
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

pub(crate) fn fnv_alpha_coverage_mode() -> AlphaCoverageMode {
    fnv::alpha_coverage_mode()
}

pub(crate) fn depth_frame(depth_provider: DepthProvider) -> DepthFrame {
    match try_depth_frame(depth_provider, crate::hooks::render_epoch()) {
        DepthAccess::Ready(frame) => frame,
        DepthAccess::Busy => DepthFrame::none(),
    }
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
    render_epoch: u32,
) -> DepthResolveOutcome {
    match depth_provider {
        DepthProvider::None => DepthResolveOutcome::Rejected,
        DepthProvider::FalloutNewVegas => unsafe {
            fnv::resolve_scene_depth(
                device_ptr,
                source_rendered_texture,
                slot,
                reason,
                render_epoch,
            )
        },
    }
}

pub(crate) fn try_depth_frame(
    depth_provider: DepthProvider,
    render_epoch: u32,
) -> DepthAccess<DepthFrame> {
    match depth_provider {
        DepthProvider::None => DepthAccess::Ready(DepthFrame::none()),
        DepthProvider::FalloutNewVegas => fnv::try_depth_frame(render_epoch),
    }
}

pub(crate) fn try_temporal_depth_epoch(
    device_ptr: *mut c_void,
    width: u32,
    height: u32,
    render_epoch: u32,
) -> DepthAccess<Option<u64>> {
    fnv::try_temporal_depth_epoch(device_ptr, width, height, render_epoch)
}

pub(crate) fn try_reset_depth_resources() -> bool {
    fnv::try_reset_depth_resources()
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

#[derive(Clone, Copy, Debug)]
pub(crate) enum DepthAccess<T> {
    Busy,
    Ready(T),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum AlphaCoverageMode {
    #[default]
    None,
    Nvidia,
    Amd,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum DepthResolveOutcome {
    Busy,
    Rejected,
    Resolved {
        depth: DepthFrame,
        underwater: UnderwaterFrame,
    },
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
    pub(crate) sky: Option<NativeSkyFrame>,
    pub(crate) atmosphere_visibility: f32,
    pub(crate) atmosphere_available: bool,
    pub(crate) first_person_rendered: bool,
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
        texture: Option<DepthTexture>,
        first_person_texture: Option<DepthTexture>,
        world_projection: DepthProjectionFrame,
        first_person_projection: DepthProjectionFrame,
        capture_epoch: u64,
    ) -> Self {
        Self {
            provider,
            texture,
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

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SunProjectionFrame {
    pub(crate) uv: [f32; 2],
    pub(crate) facing: f32,
    pub(crate) edge_fade: f32,
    pub(crate) on_screen: bool,
}

pub(crate) fn project_world_direction(
    camera: CameraFrame,
    world_direction: [f32; 3],
) -> SunProjectionFrame {
    let transform = camera.world_transform;
    if !camera.available || !transform.available || !world_direction.into_iter().all(f32::is_finite)
    {
        return SunProjectionFrame::default();
    }
    let direction_length = dot3(world_direction, world_direction).sqrt();
    if !direction_length.is_finite() || direction_length <= 0.000001 {
        return SunProjectionFrame::default();
    }
    let direction = world_direction.map(|value| value / direction_length);
    let forward = [
        transform.rotation[0][0],
        transform.rotation[1][0],
        transform.rotation[2][0],
    ];
    let up = [
        transform.rotation[0][1],
        transform.rotation[1][1],
        transform.rotation[2][1],
    ];
    let right = [
        transform.rotation[0][2],
        transform.rotation[1][2],
        transform.rotation[2][2],
    ];
    let view_x = dot3(direction, right);
    let view_y = dot3(direction, up);
    let facing = dot3(direction, forward);
    let frustum_width = camera.frustum_right - camera.frustum_left;
    let frustum_height = camera.frustum_top - camera.frustum_bottom;
    if !facing.is_finite()
        || facing <= 0.001
        || !frustum_width.is_finite()
        || !frustum_height.is_finite()
        || frustum_width <= f32::EPSILON
        || frustum_height <= f32::EPSILON
    {
        return SunProjectionFrame {
            facing: finite(facing, 0.0),
            ..SunProjectionFrame::default()
        };
    }

    let ndc_x =
        (2.0 * view_x / facing - (camera.frustum_right + camera.frustum_left)) / frustum_width;
    let ndc_y =
        (2.0 * view_y / facing - (camera.frustum_top + camera.frustum_bottom)) / frustum_height;
    let uv = [ndc_x.mul_add(0.5, 0.5), ndc_y.mul_add(-0.5, 0.5)];
    if !uv.into_iter().all(f32::is_finite) {
        return SunProjectionFrame::default();
    }
    let edge = uv[0].min(1.0 - uv[0]).min(uv[1].min(1.0 - uv[1]));
    SunProjectionFrame {
        uv,
        facing,
        edge_fade: smooth01((edge / 0.035).clamp(0.0, 1.0)),
        on_screen: edge >= 0.0,
    }
}

fn dot3(a: [f32; 3], b: [f32; 3]) -> f32 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

fn smooth01(value: f32) -> f32 {
    let value = finite(value, 0.0).clamp(0.0, 1.0);
    value * value * (3.0 - 2.0 * value)
}

fn finite(value: f32, fallback: f32) -> f32 {
    if value.is_finite() { value } else { fallback }
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
    pub(crate) fog_color: [f32; 3],
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
            fog_color: [0.0; 3],
            fog_start: 0.0,
            fog_end: 0.0,
            fog_power: 1.0,
            fog_available: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AtmosphereFrame {
    pub(crate) camera: CameraFrame,
    pub(crate) depth: DepthFrame,
    pub(crate) environment: EnvironmentFrame,
    pub(crate) underwater: UnderwaterFrame,
    pub(crate) sun: SunFrame,
    pub(crate) sky: Option<NativeSkyFrame>,
    pub(crate) material_state: MaterialStateFrame,
    pub(crate) frame_epoch: u64,
    pub(crate) distance_bound: f32,
}

impl AtmosphereFrame {
    pub(crate) fn depth_contract_failure(self) -> Option<&'static str> {
        if self.depth.texture.is_none() {
            return Some("missing current world depth");
        }
        if !self.camera.available {
            return Some("missing current world camera");
        }
        if self.depth.world_projection.reversed_depth.is_none() {
            return Some("unknown world depth direction");
        }
        if !self.distance_bound.is_finite() || self.distance_bound <= self.camera.near_z {
            return Some("invalid atmosphere distance bound");
        }
        None
    }

    pub(crate) fn underwater_contract_ready(self) -> bool {
        self.underwater.hook_available
            && self.underwater.known
            && self.underwater.frame_epoch == self.frame_epoch
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct UnderwaterFrame {
    pub(crate) frame_epoch: u64,
    pub(crate) hook_available: bool,
    pub(crate) known: bool,
    pub(crate) underwater: bool,
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

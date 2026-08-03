//! Provider-neutral ownership for scene inputs used by the D3D9 renderer.
//!
//! The backend publishes exactly one logical depth provider at a time.
//! FNV-specific capture code remains private to [`fnv`], while callers use the
//! common provider, slot, and outcome vocabulary defined here. A provider is
//! the user-visible coverage contract; a route describes how each snapshot is
//! obtained. OMV may borrow Depth Resolve's already-produced world texture
//! while still owning first-person coverage, but never issues a duplicate
//! world copy merely to preserve a provider label.
//!
//! Startup selection is deliberately fail-open for the plugin as a whole.
//! Capability conflicts may select a safe single depth producer for the
//! current session, but they never abort unrelated graphics hooks. Live menu
//! switches remain strict and retain the previous producer on rejection.

use core::ffi::c_void;
use std::sync::atomic::{AtomicU8, Ordering};

use libpsycho::os::windows::directx9::D3DSURFACE_DESC;

use crate::config::DepthProviderConfig;

mod fnv;

pub(crate) use fnv::{
    DepthCopyCounters, DepthResolveRouteStatus, DepthResolveStatus, ProviderMarkerCounters,
    WorldCameraJitter,
};

static ACTIVE_DEPTH_PROVIDER: AtomicU8 = AtomicU8::new(DepthProvider::None as u8);

/// Effective initial producer and any compatibility fallback applied to it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InitialDepthActivation {
    /// Producer requested by the loaded configuration.
    pub(crate) requested: DepthProvider,
    /// Single producer that OMV can activate safely for this session.
    pub(crate) active: DepthProvider,
    /// Explanation when `active` differs from `requested`.
    pub(crate) fallback: Option<InitialDepthFallback>,
}

/// Reason OMV selected a different initial depth producer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InitialDepthFallback {
    /// The explicitly selected external provider was not loaded.
    ExternalProviderUnavailable,
}

impl InitialDepthFallback {
    /// Return a stable user-facing explanation of the session fallback.
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::ExternalProviderUnavailable => {
                "Depth Resolve was selected but its provider exports are unavailable; depth effects are disabled for this session"
            }
        }
    }
}

pub(crate) fn d3d_device_ptr() -> Option<*mut c_void> {
    fnv::d3d_device_ptr()
}

pub(crate) fn depth_resolve_status(depth_provider: DepthProvider) -> DepthResolveStatus {
    match depth_provider {
        DepthProvider::None => DepthResolveStatus {
            route: DepthResolveRouteStatus::Unavailable,
            reason: "depth effects are disabled",
        },
        DepthProvider::FalloutNewVegas => fnv::depth_resolve_status(),
        DepthProvider::DepthResolve => fnv::external_depth_resolve_status(),
    }
}

pub(crate) fn startup_log(depth_provider: DepthProvider) {
    log::info!("[BACKEND] Active backend: Fallout New Vegas");
    log::info!("[BACKEND] Depth provider: {}", depth_provider.label());
}

/// Activate the initial depth producer at xNVSE `DeferredInit`.
///
/// Provider validation may inspect the D3D device and loaded Depth Resolve
/// module, so it must not run from `NVSEPlugin_Load`. The shared texture is
/// retained lazily on the first render capture because another DeferredInit
/// listener may still own its creation.
pub(crate) fn initialize_depth_provider(depth_provider: DepthProvider) -> InitialDepthActivation {
    // Another DeferredInit listener may own creation of the shared texture.
    // Startup selects ownership from module/capability evidence but lets the
    // first render capture retain and validate the resource after all listeners
    // have completed.
    let activation = fnv::select_initial_depth_provider(depth_provider);
    ACTIVE_DEPTH_PROVIDER.store(activation.active as u8, Ordering::Release);
    activation
}

/// Fail closed if startup cannot establish the selected producer's hook set.
///
/// Scene hooks can be individually installed before DeferredInit discovers
/// that another required boundary is unavailable. Publishing `None` prevents
/// those resident callbacks from issuing an uncoordinated OMV resolve after
/// startup returns an error; the user's persisted setting is left untouched
/// so the next launch can retry after the installation is repaired.
pub(crate) fn abandon_initial_depth_provider() {
    ACTIVE_DEPTH_PROVIDER.store(DepthProvider::None as u8, Ordering::Release);
}

/// Switch logical depth providers at an engine-owned presentation boundary.
///
/// The old provider's OMV-owned resources and snapshots are released before
/// the atomic provider identity changes. When Depth Resolve is loaded, OMV
/// deliberately borrows its world snapshots and owns only the independent
/// first-person path; this prevents duplicate NVIDIA copies without reducing
/// OMV's full world/view-model depth contract.
pub(crate) fn switch_depth_provider(depth_provider: DepthProvider) -> Result<bool, &'static str> {
    let current = active_depth_provider();
    if current == depth_provider {
        return Ok(false);
    }
    fnv::validate_depth_provider(depth_provider)?;
    if !fnv::try_reset_depth_resources() {
        return Err("depth provider resource owner is busy");
    }
    // Reset invalidates retained shared COM identity. Revalidate after release
    // so the first frame under the new provider cannot sample a stale texture.
    fnv::validate_depth_provider(depth_provider)?;
    ACTIVE_DEPTH_PROVIDER.store(depth_provider as u8, Ordering::Release);
    let markers = provider_marker_counters();
    log::info!(
        "[FNV] Depth provider switched: {} -> {}; depth_hooks={}, d3d_device_vtable=untouched; counter baseline: omv={}, external={}, external_suppressed={}, external_snapshots={}",
        current.label(),
        depth_provider.label(),
        crate::fnv_render::depth_stage_hooks_status_label(),
        markers.omv_allowed,
        markers.external_allowed,
        markers.external_suppressed,
        markers.external_publications,
    );
    Ok(true)
}

#[cfg(test)]
mod provider_switch_contract_tests {
    use super::{
        DepthProvider, InitialDepthActivation, InitialDepthFallback, choose_initial_depth_provider,
    };

    #[test]
    fn provider_switch_never_requests_driver_vtable_interposition() {
        let source = include_str!("mod.rs");
        let body = source
            .split_once("pub(crate) fn switch_depth_provider")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("pub(crate) fn active_depth_provider"))
            .map(|(body, _)| body)
            .expect("provider switch body");
        assert!(!body.contains("set_resz_interposition_active"));
        assert!(!body.contains("resz_interposition_ready"));
        assert!(!body.contains("set_depth_stage_hooks_active"));
        assert!(body.contains("ACTIVE_DEPTH_PROVIDER.store"));
    }

    #[test]
    fn native_d3d9_without_external_depth_resolve_keeps_omv_depth() {
        assert_eq!(
            choose_initial_depth_provider(DepthProvider::FalloutNewVegas, false,),
            InitialDepthActivation {
                requested: DepthProvider::FalloutNewVegas,
                active: DepthProvider::FalloutNewVegas,
                fallback: None,
            }
        );
    }

    #[test]
    fn omv_provider_keeps_full_coverage_with_external_nvapi_world_depth() {
        assert_eq!(
            choose_initial_depth_provider(DepthProvider::FalloutNewVegas, true,),
            InitialDepthActivation {
                requested: DepthProvider::FalloutNewVegas,
                active: DepthProvider::FalloutNewVegas,
                fallback: None,
            }
        );
    }

    #[test]
    fn external_route_capability_does_not_reduce_omv_coverage() {
        let activation = choose_initial_depth_provider(DepthProvider::FalloutNewVegas, true);
        assert_eq!(activation.active, DepthProvider::FalloutNewVegas);
        assert_eq!(activation.fallback, None);
    }

    #[test]
    fn missing_explicit_external_provider_disables_only_depth() {
        assert_eq!(
            choose_initial_depth_provider(DepthProvider::DepthResolve, false,),
            InitialDepthActivation {
                requested: DepthProvider::DepthResolve,
                active: DepthProvider::None,
                fallback: Some(InitialDepthFallback::ExternalProviderUnavailable),
            }
        );
    }
}

/// Choose the startup coverage contract from configuration and capabilities.
///
/// A loaded Depth Resolve can always supply OMV's world snapshot without an
/// additional copy. The OMV provider therefore remains active and adds the
/// independent first-person contract regardless of whether the external
/// producer selected RESZ or NvAPI.
fn choose_initial_depth_provider(
    requested: DepthProvider,
    external_available: bool,
) -> InitialDepthActivation {
    let (active, fallback) = match requested {
        DepthProvider::None => (DepthProvider::None, None),
        DepthProvider::DepthResolve if !external_available => (
            DepthProvider::None,
            Some(InitialDepthFallback::ExternalProviderUnavailable),
        ),
        DepthProvider::DepthResolve => (DepthProvider::DepthResolve, None),
        DepthProvider::FalloutNewVegas => (DepthProvider::FalloutNewVegas, None),
    };
    InitialDepthActivation {
        requested,
        active,
        fallback,
    }
}

/// Return the producer selected for the current render epoch.
pub(crate) fn active_depth_provider() -> DepthProvider {
    DepthProvider::from_raw(ACTIVE_DEPTH_PROVIDER.load(Ordering::Acquire))
}

pub(crate) fn camera_frame(depth_provider: DepthProvider, desc: &D3DSURFACE_DESC) -> CameraFrame {
    match depth_provider {
        DepthProvider::None => CameraFrame::fallback(desc),
        DepthProvider::FalloutNewVegas | DepthProvider::DepthResolve => fnv::camera_frame(desc),
    }
}

pub(crate) fn environment_frame(depth_provider: DepthProvider) -> EnvironmentFrame {
    match depth_provider {
        DepthProvider::None => EnvironmentFrame::default(),
        DepthProvider::FalloutNewVegas | DepthProvider::DepthResolve => fnv::environment_frame(),
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

/// Build the CPU-published atmosphere contract before a depth transaction.
///
/// The returned frame intentionally carries `DepthFrame::none()`. It is valid
/// only for the conservative atmosphere admission test; shader rendering must
/// use [`atmosphere_frame_from_depth`] so camera projection, depth direction,
/// and capture epoch stay coherent with the sampled texture.
pub(crate) fn atmosphere_frame_before_depth(
    depth_provider: DepthProvider,
    desc: &D3DSURFACE_DESC,
    user_max_distance: f32,
    frame_epoch: u32,
) -> AtmosphereFrame {
    let camera = camera_frame(depth_provider, desc);
    let environment = environment_frame(depth_provider);
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
        depth: DepthFrame::none(),
        environment,
        underwater: fnv::underwater_frame(u64::from(frame_epoch)),
        sun: sun_frame(depth_provider),
        sky: native_sky_frame(),
        material_state: material_state_frame(),
        frame_epoch: u64::from(frame_epoch),
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

pub(crate) fn fnv_third_person_view() -> Option<bool> {
    fnv::third_person_view()
}

pub(crate) fn sun_frame(depth_provider: DepthProvider) -> SunFrame {
    match depth_provider {
        DepthProvider::None => SunFrame::default(),
        DepthProvider::FalloutNewVegas | DepthProvider::DepthResolve => fnv::sun_frame(),
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
        DepthProvider::FalloutNewVegas | DepthProvider::DepthResolve => {
            fnv::rendered_texture_color_surface(rendered_texture)
        }
    }
}

pub(crate) unsafe fn resolve_scene_depth(
    depth_provider: DepthProvider,
    device_ptr: *mut c_void,
    source_rendered_texture: Option<*mut c_void>,
    slot: DepthResolveSlot,
    stage: DepthResolveStage,
    world_projection_override: Option<CameraFrame>,
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
                stage,
                world_projection_override,
                reason,
                render_epoch,
            )
        },
        DepthProvider::DepthResolve => fnv::external_depth_outcome(slot, render_epoch),
    }
}

pub(crate) fn try_depth_frame(
    depth_provider: DepthProvider,
    render_epoch: u32,
) -> DepthAccess<DepthFrame> {
    match depth_provider {
        DepthProvider::None => DepthAccess::Ready(DepthFrame::none()),
        DepthProvider::FalloutNewVegas => fnv::try_depth_frame(render_epoch),
        DepthProvider::DepthResolve => fnv::try_external_depth_frame(render_epoch),
    }
}

pub(crate) fn try_temporal_depth_epoch(
    depth_provider: DepthProvider,
    device_ptr: *mut c_void,
    width: u32,
    height: u32,
    render_epoch: u32,
) -> DepthAccess<Option<u64>> {
    match depth_provider {
        DepthProvider::None => DepthAccess::Ready(None),
        DepthProvider::FalloutNewVegas => {
            fnv::try_temporal_depth_epoch(device_ptr, width, height, render_epoch)
        }
        DepthProvider::DepthResolve => {
            fnv::try_external_temporal_depth_epoch(device_ptr, width, height, render_epoch)
        }
    }
}

pub(crate) fn try_reset_depth_resources() -> bool {
    fnv::try_reset_depth_resources()
}

/// Publish Depth Resolve's post-world snapshot without issuing a copy.
pub(crate) unsafe fn publish_external_depth_after_world(
    device_ptr: *mut c_void,
    render_epoch: u32,
) {
    if active_depth_provider() == DepthProvider::DepthResolve {
        unsafe { fnv::publish_external_depth_after_world(device_ptr, render_epoch) };
    }
}

/// Return fixed-size marker counters for runtime diagnostics.
pub(crate) fn provider_marker_counters() -> ProviderMarkerCounters {
    fnv::provider_marker_counters()
}

/// Return physical depth-copy and exact-cache counters.
pub(crate) fn depth_copy_counters() -> DepthCopyCounters {
    fnv::depth_copy_counters()
}

/// Machine-local owner of shader-readable scene depth.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum DepthProvider {
    /// OMV consumes no depth and issues no depth copy.
    #[default]
    None = 0,
    /// OMV resolves world and first-person depth.
    FalloutNewVegas = 1,
    /// OMV borrows Depth Resolve's world-only texture without issuing a copy.
    DepthResolve = 2,
}

impl DepthProvider {
    /// Return the stable configuration/diagnostic label.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::FalloutNewVegas => "omv",
            Self::DepthResolve => "depth_resolve",
        }
    }

    fn from_raw(value: u8) -> Self {
        match value {
            1 => Self::FalloutNewVegas,
            2 => Self::DepthResolve,
            _ => Self::None,
        }
    }

    /// Return whether this provider can publish world depth.
    pub(crate) fn supplies_world_depth(self) -> bool {
        self != Self::None
    }

    /// Return whether this provider can publish independent view-model depth.
    pub(crate) fn supplies_first_person_depth(self) -> bool {
        self == Self::FalloutNewVegas
    }
}

impl From<DepthProviderConfig> for DepthProvider {
    fn from(value: DepthProviderConfig) -> Self {
        match value {
            DepthProviderConfig::None => Self::None,
            DepthProviderConfig::FalloutNewVegas => Self::FalloutNewVegas,
            DepthProviderConfig::DepthResolve => Self::DepthResolve,
        }
    }
}

impl From<DepthProvider> for DepthProviderConfig {
    fn from(value: DepthProvider) -> Self {
        match value {
            DepthProvider::None => Self::None,
            DepthProvider::FalloutNewVegas => Self::FalloutNewVegas,
            DepthProvider::DepthResolve => Self::DepthResolve,
        }
    }
}

#[cfg(test)]
mod depth_provider_tests {
    use super::DepthProvider;
    use crate::config::DepthProviderConfig;

    #[test]
    fn external_provider_is_world_only_and_never_implies_hybrid_viewmodel_depth() {
        let provider = DepthProvider::from(DepthProviderConfig::DepthResolve);
        assert!(provider.supplies_world_depth());
        assert!(!provider.supplies_first_person_depth());
    }

    #[test]
    fn omv_provider_owns_both_depth_slots() {
        let provider = DepthProvider::from(DepthProviderConfig::FalloutNewVegas);
        assert!(provider.supplies_world_depth());
        assert!(provider.supplies_first_person_depth());
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DepthResolveSlot {
    World,
    FirstPerson,
}

/// Native render boundary that defines the semantic contents of a depth copy.
///
/// World pre-alpha and coherent world depth are deliberately different
/// snapshots even when they share a slot and frame epoch. Cache reuse is valid
/// only when this stage, the source surface, dimensions, slot, and epoch all
/// match.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum DepthResolveStage {
    #[default]
    PreAlphaWorld,
    CoherentWorld,
    FirstPerson,
}

impl DepthResolveStage {
    /// Return the only depth slot valid for this render boundary.
    pub(crate) const fn slot(self) -> DepthResolveSlot {
        match self {
            Self::PreAlphaWorld | Self::CoherentWorld => DepthResolveSlot::World,
            Self::FirstPerson => DepthResolveSlot::FirstPerson,
        }
    }
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
    pub(crate) third_person_view: Option<bool>,
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
            DepthProvider::DepthResolve => 3.0,
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

    pub(crate) fn with_pixel_jitter(
        self,
        jitter_pixels: [f32; 2],
        width: u32,
        height: u32,
    ) -> Option<Self> {
        if !self.available
            || width == 0
            || height == 0
            || !jitter_pixels.iter().all(|value| value.is_finite())
        {
            return None;
        }

        let frustum_width = self.frustum_right - self.frustum_left;
        let frustum_height = self.frustum_top - self.frustum_bottom;
        if !frustum_width.is_finite()
            || !frustum_height.is_finite()
            || frustum_width <= f32::EPSILON
            || frustum_height <= f32::EPSILON
        {
            return None;
        }

        let offset_x = frustum_width * jitter_pixels[0] / width as f32;
        let offset_y = frustum_height * jitter_pixels[1] / height as f32;
        let mut jittered = self;
        jittered.frustum_left += offset_x;
        jittered.frustum_right += offset_x;
        jittered.frustum_top -= offset_y;
        jittered.frustum_bottom -= offset_y;
        [
            jittered.frustum_left,
            jittered.frustum_right,
            jittered.frustum_bottom,
            jittered.frustum_top,
        ]
        .iter()
        .all(|value| value.is_finite())
        .then_some(jittered)
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

const SUN_EDGE_FADE_VIEWPORT_FRACTION: f32 = 0.12;

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
        edge_fade: smooth01((edge / SUN_EDGE_FADE_VIEWPORT_FRACTION).clamp(0.0, 1.0)),
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
    pub(crate) sampled_depth_bits: u8,
}

impl DepthProjectionFrame {
    pub(crate) fn reversed_depth_f32(self) -> f32 {
        match self.reversed_depth {
            Some(true) => 1.0,
            Some(false) => 0.0,
            None => -1.0,
        }
    }

    pub(crate) fn sampled_depth_levels(self) -> f32 {
        match self.sampled_depth_bits {
            1..=24 => ((1u32 << self.sampled_depth_bits) - 1) as f32,
            _ => 16_777_215.0,
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

#[cfg(test)]
mod camera_projection_tests {
    use super::{CameraFrame, CameraTransformFrame};

    fn camera() -> CameraFrame {
        CameraFrame {
            near_z: 5.0,
            far_z: 1000.0,
            aspect_ratio: 16.0 / 9.0,
            frustum_left: -1.0,
            frustum_right: 1.0,
            frustum_bottom: -0.5,
            frustum_top: 0.5,
            world_transform: CameraTransformFrame {
                rotation: [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
                translation: [0.0; 3],
                scale: 1.0,
                available: true,
            },
            available: true,
        }
    }

    fn center_projection_pixels(camera: CameraFrame, width: u32, height: u32) -> [f32; 2] {
        let ndc_x = -(camera.frustum_right + camera.frustum_left)
            / (camera.frustum_right - camera.frustum_left);
        let ndc_y = -(camera.frustum_top + camera.frustum_bottom)
            / (camera.frustum_top - camera.frustum_bottom);
        [
            (ndc_x * 0.5 + 0.5) * width as f32,
            (0.5 - ndc_y * 0.5) * height as f32,
        ]
    }

    #[test]
    fn pixel_jitter_projection_moves_stationary_geometry_by_the_requested_sample() {
        let width = 1920;
        let height = 1080;
        let original = camera();
        let jitter = [0.5, -0.25];
        let projected = original
            .with_pixel_jitter(jitter, width, height)
            .expect("valid jittered projection");
        let original_pixel = center_projection_pixels(original, width, height);
        let projected_pixel = center_projection_pixels(projected, width, height);

        assert!((projected_pixel[0] - original_pixel[0] + jitter[0]).abs() < 0.0002);
        assert!((projected_pixel[1] - original_pixel[1] + jitter[1]).abs() < 0.0002);
        assert_eq!(
            projected.world_transform.rotation,
            original.world_transform.rotation
        );
        assert_eq!(
            projected.world_transform.translation,
            original.world_transform.translation
        );
    }

    #[test]
    fn pixel_jitter_rejects_invalid_inputs_instead_of_publishing_bad_metadata() {
        assert!(camera().with_pixel_jitter([0.5, 0.5], 0, 1080).is_none());
        assert!(
            camera()
                .with_pixel_jitter([f32::NAN, 0.5], 1920, 1080)
                .is_none()
        );
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

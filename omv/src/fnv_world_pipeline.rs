//! Coherent nonblocking owner for Fallout New Vegas world-only effects.

use core::ffi::c_void;
use std::sync::{
    LazyLock,
    atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
};

use libpsycho::os::windows::directx9::{
    D3DFORMAT, D3DSBT_ALL, D3DSURFACE_DESC, D3DTEXF_POINT, Device9Ref, Direct3DResult, StateBlock9,
    Surface9, Texture9, direct3d_failure,
};
use parking_lot::Mutex;

use crate::{
    backend::{self, DepthAccess, DepthProvider, DepthResolveOutcome, DepthResolveSlot},
    config::{
        GraphicsMenuConfig, TemporalAaConfig as MenuTemporalAaConfig, VolumetricFogConfig,
        VolumetricLightingConfig,
    },
    effects::{
        atmosphere::{AtmosphereDrawOutcome, AtmosphereEffect, AtmosphereSettings},
        temporal_aa::{TargetDescription, TemporalAaConfig, TemporalAaEffect},
    },
};

const REQUIRE_WORLD_DEPTH: u32 = 1 << 0;
const REQUIRE_WORLD_COLOR: u32 = 1 << 1;
const REQUIRE_TEMPORAL_AA: u32 = 1 << 2;
const MAX_RUNTIME_LOGS: u32 = 32;

static CONFIG_MAILBOX: LazyLock<Mutex<PublishedConfig>> =
    LazyLock::new(|| Mutex::new(PublishedConfig::default()));
static CONFIG_GENERATION: AtomicU32 = AtomicU32::new(1);
static CONFIG_PUBLISH_PENDING: AtomicBool = AtomicBool::new(false);
static REQUIREMENTS: AtomicU32 = AtomicU32::new(0);

static WORLD_PIPELINE: LazyLock<Mutex<FnvWorldPipelineRuntime>> =
    LazyLock::new(|| Mutex::new(FnvWorldPipelineRuntime::default()));
static PENDING_EPOCH: AtomicU32 = AtomicU32::new(0);
static PENDING_TARGET: AtomicUsize = AtomicUsize::new(0);
static APPLIED_EPOCH: AtomicU32 = AtomicU32::new(0);
static APPLIED_TARGET: AtomicUsize = AtomicUsize::new(0);
static LAST_DISTANCE_BOUND: AtomicU32 = AtomicU32::new(0);
static LAST_TRANSMITTANCE: AtomicU32 = AtomicU32::new(0);
static LAST_ESTIMATE_EPOCH: AtomicU32 = AtomicU32::new(0);
static LAST_DIAGNOSTIC_ESTIMATE_EPOCH: AtomicU32 = AtomicU32::new(0);
static DIAGNOSTICS_ACTIVE: AtomicBool = AtomicBool::new(false);
static PRESENTS: AtomicU32 = AtomicU32::new(0);
static CONFIG_PUBLISH_BUSY: AtomicU32 = AtomicU32::new(0);
static CONFIG_READ_BUSY: AtomicU32 = AtomicU32::new(0);
static JITTER_LOCK_BUSY: AtomicU32 = AtomicU32::new(0);
static PRIMARY_ATTEMPTS: AtomicU32 = AtomicU32::new(0);
static PRE_ALPHA_ATTEMPTS: AtomicU32 = AtomicU32::new(0);
static PRE_ALPHA_LOCK_BUSY: AtomicU32 = AtomicU32::new(0);
static PRIMARY_LOCK_BUSY: AtomicU32 = AtomicU32::new(0);
static DEPTH_LOCK_BUSY: AtomicU32 = AtomicU32::new(0);
static RETRY_ATTEMPTS: AtomicU32 = AtomicU32::new(0);
static RETRY_LOCK_BUSY: AtomicU32 = AtomicU32::new(0);
static RETRY_COMPLETED: AtomicU32 = AtomicU32::new(0);
static APPLIED_FRAMES: AtomicU32 = AtomicU32::new(0);
static COMPLETED_WITHOUT_DRAW: AtomicU32 = AtomicU32::new(0);
static TARGET_REJECTIONS: AtomicU32 = AtomicU32::new(0);
static OUTER_TARGET_MISMATCHES: AtomicU32 = AtomicU32::new(0);
static DEADLINE_MISSES: AtomicU32 = AtomicU32::new(0);
static TRANSACTION_FAILURES: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy)]
struct WorldEffectsConfig {
    screen_space_shaders: bool,
    depth_provider: DepthProvider,
    temporal_aa: MenuTemporalAaConfig,
    fog: VolumetricFogConfig,
    lighting: VolumetricLightingConfig,
}

impl Default for WorldEffectsConfig {
    fn default() -> Self {
        Self::from_menu(GraphicsMenuConfig::default())
    }
}

impl WorldEffectsConfig {
    fn from_menu(config: GraphicsMenuConfig) -> Self {
        Self {
            screen_space_shaders: config.screen_space_shaders,
            depth_provider: config.depth_provider.into(),
            temporal_aa: config.embedded_effects.temporal_aa,
            fog: config.embedded_effects.volumetric_fog,
            lighting: config.embedded_effects.volumetric_lighting,
        }
    }

    fn atmosphere_settings(self) -> AtmosphereSettings {
        AtmosphereSettings::from_config(self.fog, self.lighting)
    }

    fn temporal_aa_enabled(self) -> bool {
        self.screen_space_shaders
            && self.depth_provider == DepthProvider::FalloutNewVegas
            && self.temporal_aa.enabled
    }

    fn requirements(self) -> u32 {
        if !self.screen_space_shaders || self.depth_provider != DepthProvider::FalloutNewVegas {
            return 0;
        }

        let settings = self.atmosphere_settings();
        let mut requirements = 0;
        if self.temporal_aa.enabled || settings.requires_depth() {
            requirements |= REQUIRE_WORLD_DEPTH;
        }
        if settings.requires_world_color() {
            requirements |= REQUIRE_WORLD_COLOR;
        }
        if self.temporal_aa.enabled {
            requirements |= REQUIRE_TEMPORAL_AA;
        }
        requirements
    }

    fn requested(self) -> bool {
        self.requirements() != 0
    }

    #[cfg(test)]
    fn requires_world_depth(self) -> bool {
        self.requirements() & REQUIRE_WORLD_DEPTH != 0
    }

    #[cfg(test)]
    fn requires_world_color(self) -> bool {
        self.requirements() & REQUIRE_WORLD_COLOR != 0
    }
}

#[derive(Clone, Copy)]
struct PublishedConfig {
    generation: u32,
    config: WorldEffectsConfig,
}

impl Default for PublishedConfig {
    fn default() -> Self {
        Self {
            generation: 1,
            config: WorldEffectsConfig::default(),
        }
    }
}

pub(crate) fn publish_config(config: GraphicsMenuConfig) -> bool {
    let Some(mut mailbox) = CONFIG_MAILBOX.try_lock() else {
        CONFIG_PUBLISH_BUSY.fetch_add(1, Ordering::Relaxed);
        CONFIG_PUBLISH_PENDING.store(true, Ordering::Release);
        return false;
    };

    let generation = CONFIG_GENERATION
        .load(Ordering::Relaxed)
        .wrapping_add(1)
        .max(1);
    let world_config = WorldEffectsConfig::from_menu(config);
    *mailbox = PublishedConfig {
        generation,
        config: world_config,
    };
    REQUIREMENTS.store(world_config.requirements(), Ordering::Release);
    crate::fnv_local_lights::configure_atmosphere(
        world_config.screen_space_shaders
            && world_config.depth_provider == DepthProvider::FalloutNewVegas
            && world_config.lighting.local_lights_enabled,
    );
    LAST_ESTIMATE_EPOCH.store(0, Ordering::Release);
    LAST_DIAGNOSTIC_ESTIMATE_EPOCH.store(0, Ordering::Release);
    CONFIG_GENERATION.store(generation, Ordering::Release);
    CONFIG_PUBLISH_PENDING.store(false, Ordering::Release);
    true
}

pub(crate) fn config_publish_pending() -> bool {
    CONFIG_PUBLISH_PENDING.load(Ordering::Acquire)
}

pub(crate) fn needs_depth(slot: DepthResolveSlot) -> bool {
    match slot {
        DepthResolveSlot::World => REQUIREMENTS.load(Ordering::Acquire) & REQUIRE_WORLD_DEPTH != 0,
        DepthResolveSlot::FirstPerson => false,
    }
}

pub(crate) fn needs_temporal_aa() -> bool {
    REQUIREMENTS.load(Ordering::Acquire) & REQUIRE_TEMPORAL_AA != 0
}

pub(crate) fn needs_atmosphere() -> bool {
    REQUIREMENTS.load(Ordering::Acquire) & REQUIRE_WORLD_COLOR != 0
}

pub(crate) fn fog_estimate() -> Option<(f32, f32)> {
    (LAST_DIAGNOSTIC_ESTIMATE_EPOCH.load(Ordering::Acquire) != 0).then(|| {
        (
            f32::from_bits(LAST_DISTANCE_BOUND.load(Ordering::Acquire)),
            f32::from_bits(LAST_TRANSMITTANCE.load(Ordering::Acquire)),
        )
    })
}

pub(crate) fn set_diagnostics_active(active: bool) {
    if DIAGNOSTICS_ACTIVE.swap(active, Ordering::AcqRel) != active {
        LAST_DIAGNOSTIC_ESTIMATE_EPOCH.store(0, Ordering::Release);
    }
}

pub(crate) fn atmosphere_visibility() -> Option<f32> {
    (LAST_ESTIMATE_EPOCH.load(Ordering::Acquire) == crate::hooks::render_epoch())
        .then(|| 1.0 - f32::from_bits(LAST_TRANSMITTANCE.load(Ordering::Acquire)).clamp(0.0, 1.0))
}

pub(crate) unsafe fn begin_temporal_aa_jitter(
    device_ptr: *mut c_void,
    target_surface: usize,
    target: TargetDescription,
) -> Option<backend::WorldCameraJitter> {
    if !needs_temporal_aa() {
        return None;
    }
    let Some(mut runtime) = WORLD_PIPELINE.try_lock() else {
        JITTER_LOCK_BUSY.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    unsafe { runtime.temporal_aa_jitter(device_ptr, target_surface, target) }
}

pub(crate) unsafe fn apply_primary(device_ptr: *mut c_void) {
    if REQUIREMENTS.load(Ordering::Acquire) == 0 {
        return;
    }

    let epoch = crate::hooks::render_epoch();
    let attempts = PRIMARY_ATTEMPTS.fetch_add(1, Ordering::Relaxed) + 1;
    if attempts == 1 {
        log::info!(
            "[FNV WORLD] Nonblocking epoch/target transaction active: primary world boundary with one pre-first-person retry"
        );
    }
    let target = current_device_target(device_ptr).unwrap_or(0);
    let Some(mut runtime) = WORLD_PIPELINE.try_lock() else {
        PRIMARY_LOCK_BUSY.fetch_add(1, Ordering::Relaxed);
        if target != 0 {
            publish_pending(epoch, target);
        }
        return;
    };

    if let Err(err) = unsafe { runtime.apply(device_ptr, epoch, target, ApplyOrigin::Primary) } {
        runtime.log_error("primary", &err);
    }
}

pub(crate) unsafe fn apply_before_alpha(device_ptr: *mut c_void) {
    if !needs_atmosphere() {
        return;
    }

    let epoch = crate::hooks::render_epoch();
    PRE_ALPHA_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    let target = current_device_target(device_ptr).unwrap_or(0);
    let Some(mut runtime) = WORLD_PIPELINE.try_lock() else {
        PRE_ALPHA_LOCK_BUSY.fetch_add(1, Ordering::Relaxed);
        return;
    };
    if let Err(err) = unsafe { runtime.apply_atmosphere_before_alpha(device_ptr, epoch, target) } {
        runtime.log_error("before_alpha", &err);
    }
}

pub(crate) unsafe fn retry_before_first_person(
    device_ptr: *mut c_void,
    rendered_texture: *mut c_void,
) {
    let epoch = crate::hooks::render_epoch();
    if PENDING_EPOCH.load(Ordering::Acquire) != epoch {
        return;
    }
    let pending_target = PENDING_TARGET.load(Ordering::Acquire);
    let Some(rendered_surface) =
        backend::rendered_texture_color_surface(DepthProvider::FalloutNewVegas, rendered_texture)
    else {
        return;
    };
    if rendered_surface as usize != pending_target {
        return;
    }
    let Some(current_target) = current_device_target(device_ptr) else {
        return;
    };
    if !retry_target_matches(
        epoch,
        PENDING_EPOCH.load(Ordering::Acquire),
        pending_target,
        rendered_surface as usize,
        current_target,
    ) {
        return;
    }

    RETRY_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    let Some(mut runtime) = WORLD_PIPELINE.try_lock() else {
        RETRY_LOCK_BUSY.fetch_add(1, Ordering::Relaxed);
        return;
    };
    if let Err(err) = unsafe {
        runtime.apply(
            device_ptr,
            epoch,
            pending_target,
            ApplyOrigin::BeforeFirstPerson,
        )
    } {
        runtime.log_error("before_first_person", &err);
    }
}

fn retry_target_matches(
    epoch: u32,
    pending_epoch: u32,
    pending_target: usize,
    rendered_target: usize,
    current_target: usize,
) -> bool {
    pending_epoch == epoch
        && pending_target != 0
        && rendered_target == pending_target
        && current_target == pending_target
}

pub(crate) fn close_deadline(source_rendered_texture: *mut c_void) {
    let epoch = crate::hooks::render_epoch();
    if PENDING_EPOCH.load(Ordering::Acquire) != epoch {
        return;
    }

    let pending_target = PENDING_TARGET.load(Ordering::Acquire);
    let source_target = backend::rendered_texture_color_surface(
        DepthProvider::FalloutNewVegas,
        source_rendered_texture,
    )
    .map_or(0, |surface| surface as usize);
    let boundary = if source_target == pending_target {
        "image_space"
    } else {
        OUTER_TARGET_MISMATCHES.fetch_add(1, Ordering::Relaxed);
        "image_space_target_mismatch"
    };
    PENDING_EPOCH.store(0, Ordering::Release);
    PENDING_TARGET.store(0, Ordering::Release);
    record_deadline_miss(epoch, boundary);
}

pub(crate) fn finish_present(epoch: u32) {
    if !crate::fnv_local_lights::atmosphere_capture_enabled()
        && let Some(mut runtime) = WORLD_PIPELINE.try_lock()
    {
        runtime.local_lights = None;
    }
    if PENDING_EPOCH.load(Ordering::Acquire) == epoch {
        PENDING_EPOCH.store(0, Ordering::Release);
        PENDING_TARGET.store(0, Ordering::Release);
        record_deadline_miss(epoch, "present");
    }
    let presents = PRESENTS.fetch_add(1, Ordering::Relaxed) + 1;
    if PRIMARY_ATTEMPTS.load(Ordering::Relaxed) != 0 && presents % 600 == 0 {
        log::info!(
            "[FNV WORLD] Reliability: presents={}, pre_alpha={}/busy={}, primary={}, applied={}, completed_no_draw={}, config_publish_busy={}, config_read_busy={}, jitter_busy={}, primary_busy={}, depth_busy={}, retries={}, retry_busy={}, retry_completed={}, target_rejected={}, outer_target_mismatch={}, deadline_missed={}, failures={}",
            presents,
            PRE_ALPHA_ATTEMPTS.load(Ordering::Relaxed),
            PRE_ALPHA_LOCK_BUSY.load(Ordering::Relaxed),
            PRIMARY_ATTEMPTS.load(Ordering::Relaxed),
            APPLIED_FRAMES.load(Ordering::Relaxed),
            COMPLETED_WITHOUT_DRAW.load(Ordering::Relaxed),
            CONFIG_PUBLISH_BUSY.load(Ordering::Relaxed),
            CONFIG_READ_BUSY.load(Ordering::Relaxed),
            JITTER_LOCK_BUSY.load(Ordering::Relaxed),
            PRIMARY_LOCK_BUSY.load(Ordering::Relaxed),
            DEPTH_LOCK_BUSY.load(Ordering::Relaxed),
            RETRY_ATTEMPTS.load(Ordering::Relaxed),
            RETRY_LOCK_BUSY.load(Ordering::Relaxed),
            RETRY_COMPLETED.load(Ordering::Relaxed),
            TARGET_REJECTIONS.load(Ordering::Relaxed),
            OUTER_TARGET_MISMATCHES.load(Ordering::Relaxed),
            DEADLINE_MISSES.load(Ordering::Relaxed),
            TRANSACTION_FAILURES.load(Ordering::Relaxed),
        );
    }
}

fn record_deadline_miss(epoch: u32, boundary: &'static str) {
    let misses = DEADLINE_MISSES.fetch_add(1, Ordering::Relaxed) + 1;
    if APPLIED_EPOCH.load(Ordering::Acquire) != epoch && misses <= 8 {
        log::warn!("[FNV WORLD] Effects deadline missed: epoch={epoch}, boundary={boundary}");
    }
}

pub(crate) fn try_release_device_resources_after<F>(device_ptr: *mut c_void, after: F) -> bool
where
    F: FnOnce() -> bool,
{
    let Some(mut runtime) = WORLD_PIPELINE.try_lock() else {
        return false;
    };
    if !after() {
        return false;
    }
    runtime.release_if_device(device_ptr);
    true
}

fn publish_pending(epoch: u32, target: usize) {
    if target == 0 || APPLIED_EPOCH.load(Ordering::Acquire) == epoch {
        return;
    }
    PENDING_TARGET.store(target, Ordering::Release);
    PENDING_EPOCH.store(epoch, Ordering::Release);
}

fn clear_pending(epoch: u32, target: usize) {
    if PENDING_EPOCH.load(Ordering::Acquire) == epoch
        && PENDING_TARGET.load(Ordering::Acquire) == target
    {
        PENDING_EPOCH.store(0, Ordering::Release);
        PENDING_TARGET.store(0, Ordering::Release);
    }
}

fn current_device_target(device_ptr: *mut c_void) -> Option<usize> {
    let device = unsafe { Device9Ref::from_raw_void(device_ptr) }?;
    device
        .render_target(0)
        .ok()
        .map(|surface| surface.as_raw() as usize)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApplyOrigin {
    Primary,
    BeforeFirstPerson,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EpochOutcome {
    Pending,
    Applied,
    CompletedWithoutDraw,
    Rejected,
    Failed,
}

struct EpochState {
    epoch: u32,
    target: usize,
    outcome: EpochOutcome,
    atmosphere_complete: bool,
    atmosphere_drew: bool,
}

#[derive(Clone, Copy)]
struct TemporalProjectionOverride {
    epoch: u32,
    target_surface: usize,
    target: TargetDescription,
    rendered_camera: backend::CameraFrame,
    output_camera: backend::CameraFrame,
}

impl TemporalProjectionOverride {
    fn cameras_for(
        self,
        epoch: u32,
        target_surface: usize,
        target: TargetDescription,
    ) -> Option<TemporalProjectionCameras> {
        (self.epoch == epoch
            && self.target_surface != 0
            && self.target_surface == target_surface
            && self.target == target)
            .then_some(TemporalProjectionCameras {
                rendered: self.rendered_camera,
                output: self.output_camera,
            })
    }
}

#[derive(Clone, Copy)]
struct TemporalProjectionCameras {
    rendered: backend::CameraFrame,
    output: backend::CameraFrame,
}

fn record_pre_alpha_outcome(epoch: &mut EpochState, outcome: AtmosphereDrawOutcome) {
    let drew = outcome.drew();
    epoch.atmosphere_complete = outcome.completes_pre_alpha();
    epoch.atmosphere_drew = drew;
}

impl Default for EpochState {
    fn default() -> Self {
        Self {
            epoch: 0,
            target: 0,
            outcome: EpochOutcome::CompletedWithoutDraw,
            atmosphere_complete: false,
            atmosphere_drew: false,
        }
    }
}

#[derive(Default)]
struct FnvWorldPipelineRuntime {
    device_ptr: usize,
    config_generation: u32,
    config: WorldEffectsConfig,
    epoch: EpochState,
    frame_index: u64,
    temporal_aa: Option<TemporalAaEffect>,
    temporal_aa_creation_failed: bool,
    temporal_projection_override: Option<TemporalProjectionOverride>,
    atmosphere: Option<AtmosphereEffect>,
    atmosphere_creation_failed: bool,
    local_lights: Option<crate::fnv_local_lights::LocalLightEpoch>,
    world_color: Option<WorldColorCopy>,
    state_block: Option<StateBlock9>,
    runtime_logs: u32,
}

impl FnvWorldPipelineRuntime {
    unsafe fn apply_atmosphere_before_alpha(
        &mut self,
        device_ptr: *mut c_void,
        epoch: u32,
        target: usize,
    ) -> Direct3DResult<()> {
        self.refresh_config();
        self.begin_epoch(epoch);
        let settings = self.config.atmosphere_settings();
        if !settings.requires_world_color() || self.epoch.atmosphere_complete {
            return Ok(());
        }
        if target == 0 || current_device_target(device_ptr) != Some(target) {
            return Ok(());
        }
        let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
            return Ok(());
        };
        self.ensure_device(device_ptr);
        let world_target = device.render_target(0)?;
        if world_target.as_raw() as usize != target {
            return Ok(());
        }
        let desc = world_target.desc()?;
        if desc.Width == 0 || desc.Height == 0 {
            return Ok(());
        }
        let projection_override = self
            .temporal_projection_override
            .and_then(|projection| {
                projection.cameras_for(epoch, target, TargetDescription::from(&desc))
            })
            .map(|projection| projection.rendered);
        let depth = match unsafe {
            backend::resolve_scene_depth(
                self.config.depth_provider,
                device_ptr,
                None,
                DepthResolveSlot::World,
                projection_override,
                "FNV atmosphere before alpha coverage",
                epoch,
            )
        } {
            DepthResolveOutcome::Busy => {
                DEPTH_LOCK_BUSY.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            DepthResolveOutcome::Rejected => return Ok(()),
            DepthResolveOutcome::Resolved { depth, underwater } => (depth, underwater),
        };

        let outcome =
            self.draw_atmosphere(&device, &world_target, &desc, depth, settings, true, epoch)?;
        record_pre_alpha_outcome(&mut self.epoch, outcome);
        Ok(())
    }

    unsafe fn temporal_aa_jitter(
        &mut self,
        device_ptr: *mut c_void,
        target_surface: usize,
        target: TargetDescription,
    ) -> Option<backend::WorldCameraJitter> {
        self.temporal_projection_override = None;
        self.refresh_config();
        if target_surface == 0
            || !self.config.temporal_aa_enabled()
            || self.temporal_aa_creation_failed
        {
            return None;
        }
        let device = unsafe { Device9Ref::from_raw_void(device_ptr) }?;
        self.ensure_device(device_ptr);
        if self.temporal_aa.is_none() {
            match TemporalAaEffect::create(&device) {
                Ok(effect) => {
                    self.temporal_aa = Some(effect);
                    log::info!("[TAA] World temporal resolve initialized");
                }
                Err(err) => {
                    self.temporal_aa_creation_failed = true;
                    self.log_error("jitter_init", &err);
                    return None;
                }
            }
        }

        let epoch = crate::hooks::render_epoch();
        let depth_epoch =
            match backend::try_temporal_depth_epoch(device_ptr, target.width, target.height, epoch)
            {
                DepthAccess::Ready(Some(epoch)) => epoch,
                DepthAccess::Ready(None) | DepthAccess::Busy => return None,
            };
        let camera = backend::fnv_world_camera_frame(target.width, target.height)?;
        if !self
            .temporal_aa
            .as_ref()
            .is_some_and(|effect| effect.can_jitter(camera, depth_epoch, target))
        {
            return None;
        }

        let config = TemporalAaConfig::from_config(self.config.temporal_aa);
        let sample_index = self.frame_index.wrapping_add(1);
        let jitter_pixels = [
            (halton(sample_index, 2) - 0.5) * config.jitter_scale(),
            (halton(sample_index, 3) - 0.5) * config.jitter_scale(),
        ];
        let camera_jitter = unsafe {
            backend::jitter_fnv_world_camera(jitter_pixels, target.width, target.height)?
        };
        // The live camera is restored before a nonblocking retry. Retain both
        // the projection that sampled depth and the fixed output projection:
        // reconstruction needs the former, while temporal motion must exclude
        // Halton jitter so a still camera remains a null motion vector.
        self.temporal_projection_override = Some(TemporalProjectionOverride {
            epoch,
            target_surface,
            target,
            rendered_camera: camera_jitter.projection(),
            output_camera: camera_jitter.unjittered_projection(),
        });
        Some(camera_jitter)
    }

    unsafe fn apply(
        &mut self,
        device_ptr: *mut c_void,
        epoch: u32,
        target: usize,
        origin: ApplyOrigin,
    ) -> Direct3DResult<()> {
        self.refresh_config();
        self.begin_epoch(epoch);
        if !self.config.requested() {
            self.epoch.outcome = EpochOutcome::CompletedWithoutDraw;
            clear_pending(epoch, target);
            return Ok(());
        }
        if target == 0 || current_device_target(device_ptr) != Some(target) {
            self.epoch.outcome = EpochOutcome::Rejected;
            TARGET_REJECTIONS.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        if APPLIED_EPOCH.load(Ordering::Acquire) == epoch
            && APPLIED_TARGET.load(Ordering::Acquire) == target
        {
            self.epoch.outcome = EpochOutcome::Applied;
            clear_pending(epoch, target);
            return Ok(());
        }

        let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
            self.epoch.outcome = EpochOutcome::Rejected;
            return Ok(());
        };
        self.ensure_device(device_ptr);
        let world_target = device.render_target(0)?;
        if world_target.as_raw() as usize != target {
            self.epoch.outcome = EpochOutcome::Rejected;
            TARGET_REJECTIONS.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        let desc = world_target.desc()?;
        if desc.Width == 0 || desc.Height == 0 {
            self.epoch.outcome = EpochOutcome::Rejected;
            return Ok(());
        }
        let temporal_projection = self.temporal_projection_override.and_then(|projection| {
            projection.cameras_for(epoch, target, TargetDescription::from(&desc))
        });
        let projection_override = temporal_projection.map(|projection| projection.rendered);

        let settings = self.config.atmosphere_settings();
        let atmosphere_remaining =
            settings.requires_world_color() && !self.epoch.atmosphere_complete;
        if !self.config.temporal_aa_enabled() && !atmosphere_remaining {
            return self.finish_epoch(epoch, target, origin, self.epoch.atmosphere_drew);
        }

        let depth = match unsafe {
            backend::resolve_scene_depth(
                self.config.depth_provider,
                device_ptr,
                None,
                DepthResolveSlot::World,
                projection_override,
                match origin {
                    ApplyOrigin::Primary => "FNV coherent world transaction",
                    ApplyOrigin::BeforeFirstPerson => "FNV world transaction retry",
                },
                epoch,
            )
        } {
            DepthResolveOutcome::Busy => {
                self.epoch.outcome = EpochOutcome::Pending;
                DEPTH_LOCK_BUSY.fetch_add(1, Ordering::Relaxed);
                publish_pending(epoch, target);
                return Ok(());
            }
            DepthResolveOutcome::Rejected => {
                self.epoch.outcome = EpochOutcome::Rejected;
                clear_pending(epoch, target);
                return Ok(());
            }
            DepthResolveOutcome::Resolved { depth, underwater } => (depth, underwater),
        };

        let mut drew = self.epoch.atmosphere_drew;
        if self.config.temporal_aa_enabled() {
            self.ensure_temporal_aa(&device)?;
            let temporal_aa_ready = self.temporal_aa.is_some();
            self.ensure_state_block(&device)?;
            let attachments = RenderAttachments::capture(&device, world_target.clone())?;
            let state_block = self
                .state_block
                .as_ref()
                .ok_or_else(|| runtime_error("missing TAA state block"))?;
            state_block.capture()?;
            let mut result = self.temporal_aa.as_mut().map_or(Ok(()), |effect| {
                let output_camera = temporal_projection
                    .map_or(depth.0.world_projection.camera, |projection| {
                        projection.output
                    });
                effect.draw(
                    &device,
                    &world_target,
                    &desc,
                    depth.0,
                    output_camera,
                    TemporalAaConfig::from_config(self.config.temporal_aa),
                )
            });
            keep_first_error(&mut result, attachments.restore(&device));
            keep_first_error(&mut result, state_block.apply());
            result?;
            drew |= temporal_aa_ready;
        }

        if atmosphere_remaining {
            let taa_alpha_ready = !self.config.temporal_aa_enabled()
                || self.temporal_aa.as_ref().is_some_and(|effect| {
                    effect.alpha_preserving_history_ready(TargetDescription::from(&desc))
                });
            let outcome = self.draw_atmosphere(
                &device,
                &world_target,
                &desc,
                depth,
                settings,
                taa_alpha_ready,
                epoch,
            )?;
            self.epoch.atmosphere_complete = true;
            self.epoch.atmosphere_drew = outcome.drew();
            drew |= outcome.drew();
        }

        self.finish_epoch(epoch, target, origin, drew)
    }

    #[allow(clippy::too_many_arguments)]
    fn draw_atmosphere(
        &mut self,
        device: &Device9Ref<'_>,
        world_target: &Surface9,
        desc: &D3DSURFACE_DESC,
        depth: (backend::DepthFrame, backend::UnderwaterFrame),
        settings: AtmosphereSettings,
        taa_alpha_ready: bool,
        epoch: u32,
    ) -> Direct3DResult<AtmosphereDrawOutcome> {
        if settings.local_lights_enabled {
            let _ = crate::fnv_local_lights::try_take_published(
                &mut self.local_lights,
                device.as_raw() as usize,
            );
        } else {
            self.local_lights = None;
        }
        self.capture_world_color(device, world_target, desc)?;
        self.ensure_atmosphere(device)?;
        self.ensure_state_block(device)?;
        let frame = backend::atmosphere_frame_from_depth(
            self.config.depth_provider,
            desc,
            settings.max_distance,
            depth.0,
            depth.1,
        );
        let attachments = RenderAttachments::capture(device, world_target.clone())?;
        let state_block = self
            .state_block
            .as_ref()
            .ok_or_else(|| runtime_error("missing atmosphere state block"))?;
        state_block.capture()?;
        let world_color = self.world_color.as_ref().map(|copy| &copy.texture);
        let mut result =
            self.atmosphere
                .as_mut()
                .map_or(Ok(AtmosphereDrawOutcome::Skipped), |effect| {
                    effect.draw(
                        device,
                        world_target,
                        desc,
                        frame,
                        world_color,
                        settings,
                        self.config.temporal_aa_enabled(),
                        taa_alpha_ready,
                        self.local_lights.as_ref(),
                    )
                });
        let mut restore = attachments.restore(device);
        keep_first_error(&mut restore, state_block.apply());
        if result.is_ok() && restore.is_err() {
            result = restore.map(|_| AtmosphereDrawOutcome::Skipped);
        }
        let outcome = result?;
        if outcome.drew() {
            LAST_TRANSMITTANCE.store(
                settings.estimated_horizontal_transmittance(frame).to_bits(),
                Ordering::Release,
            );
            LAST_ESTIMATE_EPOCH.store(epoch, Ordering::Release);
            if DIAGNOSTICS_ACTIVE.load(Ordering::Relaxed) {
                LAST_DISTANCE_BOUND.store(frame.distance_bound.to_bits(), Ordering::Release);
                LAST_DIAGNOSTIC_ESTIMATE_EPOCH.store(epoch, Ordering::Release);
            }
        }
        Ok(outcome)
    }

    fn finish_epoch(
        &mut self,
        epoch: u32,
        target: usize,
        origin: ApplyOrigin,
        drew: bool,
    ) -> Direct3DResult<()> {
        self.epoch.target = target;
        self.epoch.outcome = if drew {
            APPLIED_FRAMES.fetch_add(1, Ordering::Relaxed);
            EpochOutcome::Applied
        } else {
            COMPLETED_WITHOUT_DRAW.fetch_add(1, Ordering::Relaxed);
            EpochOutcome::CompletedWithoutDraw
        };
        if origin == ApplyOrigin::BeforeFirstPerson {
            RETRY_COMPLETED.fetch_add(1, Ordering::Relaxed);
        }
        APPLIED_TARGET.store(target, Ordering::Release);
        APPLIED_EPOCH.store(epoch, Ordering::Release);
        clear_pending(epoch, target);
        Ok(())
    }

    fn begin_epoch(&mut self, epoch: u32) {
        if self.epoch.epoch == epoch {
            return;
        }
        self.epoch = EpochState {
            epoch,
            target: 0,
            outcome: EpochOutcome::Pending,
            atmosphere_complete: false,
            atmosphere_drew: false,
        };
        self.frame_index = self.frame_index.wrapping_add(1);
    }

    fn refresh_config(&mut self) {
        let generation = CONFIG_GENERATION.load(Ordering::Acquire);
        if self.config_generation == generation {
            return;
        }
        let Some(published) = CONFIG_MAILBOX.try_lock() else {
            CONFIG_READ_BUSY.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if published.generation == generation {
            self.config = published.config;
            self.config_generation = generation;
        }
    }

    fn ensure_device(&mut self, device_ptr: *mut c_void) {
        if self.device_ptr != 0 && self.device_ptr != device_ptr as usize {
            self.release();
        }
        self.device_ptr = device_ptr as usize;
    }

    fn ensure_temporal_aa(&mut self, device: &Device9Ref<'_>) -> Direct3DResult<()> {
        if self.temporal_aa.is_some() || self.temporal_aa_creation_failed {
            return Ok(());
        }
        match TemporalAaEffect::create(device) {
            Ok(effect) => {
                self.temporal_aa = Some(effect);
                log::info!("[TAA] World temporal resolve initialized");
                Ok(())
            }
            Err(err) => {
                self.temporal_aa_creation_failed = true;
                Err(err)
            }
        }
    }

    fn ensure_atmosphere(&mut self, device: &Device9Ref<'_>) -> Direct3DResult<()> {
        if self.atmosphere.is_some() || self.atmosphere_creation_failed {
            return Ok(());
        }
        match AtmosphereEffect::create(device) {
            Ok(effect) => {
                self.atmosphere = Some(effect);
                log::info!("[ATMOSPHERE] Strict-FP16 world pipeline initialized");
                Ok(())
            }
            Err(err) => {
                self.atmosphere_creation_failed = true;
                Err(err)
            }
        }
    }

    fn ensure_state_block(&mut self, device: &Device9Ref<'_>) -> Direct3DResult<()> {
        if self.state_block.is_none() {
            self.state_block = Some(device.create_state_block(D3DSBT_ALL)?);
        }
        Ok(())
    }

    fn capture_world_color(
        &mut self,
        device: &Device9Ref<'_>,
        world_target: &Surface9,
        desc: &D3DSURFACE_DESC,
    ) -> Direct3DResult<()> {
        let needs_copy = self
            .world_color
            .as_ref()
            .is_none_or(|copy| !copy.matches(desc));
        if needs_copy {
            self.world_color = Some(WorldColorCopy::create(device, desc)?);
        }
        let copy = self
            .world_color
            .as_ref()
            .ok_or_else(|| runtime_error("missing world-color copy"))?;
        device.stretch_rect(world_target, None, &copy.surface, None, D3DTEXF_POINT)
    }

    fn release_if_device(&mut self, device_ptr: *mut c_void) {
        if self.device_ptr == 0 || self.device_ptr == device_ptr as usize {
            self.release();
        }
    }

    fn release(&mut self) {
        self.device_ptr = 0;
        self.temporal_aa = None;
        self.temporal_aa_creation_failed = false;
        self.temporal_projection_override = None;
        self.atmosphere = None;
        self.atmosphere_creation_failed = false;
        self.local_lights = None;
        self.world_color = None;
        self.state_block = None;
        self.epoch = EpochState::default();
    }

    fn log_error(&mut self, phase: &'static str, err: &impl core::fmt::Display) {
        self.epoch.outcome = EpochOutcome::Failed;
        TRANSACTION_FAILURES.fetch_add(1, Ordering::Relaxed);
        if self.runtime_logs < MAX_RUNTIME_LOGS {
            log::warn!("[FNV WORLD] {phase} transaction failed: {err}");
            self.runtime_logs += 1;
        }
    }
}

struct WorldColorCopy {
    width: u32,
    height: u32,
    format: D3DFORMAT,
    texture: Texture9,
    surface: Surface9,
}

impl WorldColorCopy {
    fn create(device: &Device9Ref<'_>, desc: &D3DSURFACE_DESC) -> Direct3DResult<Self> {
        let texture = device.create_render_target_texture(desc.Width, desc.Height, desc.Format)?;
        let surface = texture.surface_level(0)?;
        Ok(Self {
            width: desc.Width,
            height: desc.Height,
            format: desc.Format,
            texture,
            surface,
        })
    }

    fn matches(&self, desc: &D3DSURFACE_DESC) -> bool {
        self.width == desc.Width && self.height == desc.Height && self.format == desc.Format
    }
}

struct RenderAttachments {
    target0: Surface9,
    target1: Option<Surface9>,
    target2: Option<Surface9>,
    target3: Option<Surface9>,
    depth: Option<Surface9>,
}

impl RenderAttachments {
    fn capture(device: &Device9Ref<'_>, target0: Surface9) -> Direct3DResult<Self> {
        Ok(Self {
            target0,
            target1: device.optional_render_target(1)?,
            target2: device.optional_render_target(2)?,
            target3: device.optional_render_target(3)?,
            depth: device.depth_stencil_surface()?,
        })
    }

    fn restore(&self, device: &Device9Ref<'_>) -> Direct3DResult<()> {
        let mut result = device.set_depth_stencil_surface(None);
        for index in 1..=3 {
            keep_first_error(&mut result, device.clear_render_target(index));
        }
        keep_first_error(&mut result, device.set_render_target(0, &self.target0));
        keep_first_error(
            &mut result,
            restore_target(device, 1, self.target1.as_ref()),
        );
        keep_first_error(
            &mut result,
            restore_target(device, 2, self.target2.as_ref()),
        );
        keep_first_error(
            &mut result,
            restore_target(device, 3, self.target3.as_ref()),
        );
        keep_first_error(
            &mut result,
            device.set_depth_stencil_surface(self.depth.as_ref()),
        );
        result
    }
}

fn restore_target(
    device: &Device9Ref<'_>,
    index: u32,
    target: Option<&Surface9>,
) -> Direct3DResult<()> {
    match target {
        Some(target) => device.set_render_target(index, target),
        None => device.clear_render_target(index),
    }
}

fn keep_first_error(result: &mut Direct3DResult<()>, next: Direct3DResult<()>) {
    if result.is_ok() && next.is_err() {
        *result = next;
    }
}

fn runtime_error(message: &'static str) -> libpsycho::os::windows::directx9::Direct3DError {
    log::warn!("[FNV WORLD] {message}");
    direct3d_failure()
}

fn halton(mut index: u64, base: u64) -> f32 {
    let mut fraction = 1.0f32;
    let mut value = 0.0f32;
    while index > 0 {
        fraction /= base as f32;
        value += fraction * (index % base) as f32;
        index /= base;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::{
        CONFIG_GENERATION, CONFIG_MAILBOX, EpochState, TemporalProjectionOverride,
        WorldEffectsConfig, halton, publish_config, record_pre_alpha_outcome, retry_target_matches,
    };
    use crate::{
        backend::{CameraFrame, CameraTransformFrame, DepthProvider},
        config::GraphicsMenuConfig,
        effects::{atmosphere::AtmosphereDrawOutcome, temporal_aa::TargetDescription},
    };
    use libpsycho::os::windows::directx9::D3DFMT_A8R8G8B8;
    use std::sync::atomic::Ordering;

    #[test]
    fn production_atmosphere_defaults_request_coherent_world_inputs() {
        let config = WorldEffectsConfig::from_menu(GraphicsMenuConfig::default());
        assert!(config.requires_world_depth());
        assert!(config.requires_world_color());
    }

    #[test]
    fn production_fog_requests_coherent_depth_and_color() {
        let mut menu = GraphicsMenuConfig::default();
        menu.depth_provider = crate::config::DepthProviderConfig::FalloutNewVegas;
        menu.embedded_effects.volumetric_fog.enabled = true;
        let config = WorldEffectsConfig::from_menu(menu);
        assert_eq!(config.depth_provider, DepthProvider::FalloutNewVegas);
        assert!(config.requires_world_depth());
        assert!(config.requires_world_color());
    }

    #[test]
    fn production_lighting_requests_coherent_depth_and_color() {
        let mut menu = GraphicsMenuConfig::default();
        menu.depth_provider = crate::config::DepthProviderConfig::FalloutNewVegas;
        menu.embedded_effects.volumetric_fog.enabled = false;
        menu.embedded_effects.volumetric_lighting.enabled = true;
        let config = WorldEffectsConfig::from_menu(menu);
        assert_eq!(config.depth_provider, DepthProvider::FalloutNewVegas);
        assert!(config.requires_world_depth());
        assert!(config.requires_world_color());
    }

    #[test]
    fn local_lights_request_world_inputs_without_directional_sun_lighting() {
        let mut menu = GraphicsMenuConfig::default();
        menu.depth_provider = crate::config::DepthProviderConfig::FalloutNewVegas;
        menu.embedded_effects.volumetric_lighting.enabled = false;
        menu.embedded_effects
            .volumetric_lighting
            .local_lights_enabled = true;
        let config = WorldEffectsConfig::from_menu(menu);

        assert!(config.requires_world_depth());
        assert!(config.requires_world_color());
    }

    #[test]
    fn halton_samples_are_bounded() {
        for index in 1..100 {
            assert!((0.0..1.0).contains(&halton(index, 2)));
        }
    }

    #[test]
    fn busy_config_mailbox_keeps_the_last_complete_generation() {
        let mailbox = CONFIG_MAILBOX.try_lock().expect("config mailbox");
        let generation = CONFIG_GENERATION.load(Ordering::Acquire);
        assert!(!publish_config(GraphicsMenuConfig::default()));
        assert_eq!(CONFIG_GENERATION.load(Ordering::Acquire), generation);
        drop(mailbox);
        assert!(publish_config(GraphicsMenuConfig::default()));
        assert_ne!(CONFIG_GENERATION.load(Ordering::Acquire), generation);
    }

    #[test]
    fn retry_requires_the_same_epoch_and_exact_world_target() {
        assert!(retry_target_matches(7, 7, 0x1234, 0x1234, 0x1234));
        assert!(!retry_target_matches(7, 6, 0x1234, 0x1234, 0x1234));
        assert!(!retry_target_matches(7, 7, 0x1234, 0x5678, 0x1234));
        assert!(!retry_target_matches(7, 7, 0x1234, 0x1234, 0x5678));
        assert!(!retry_target_matches(7, 7, 0, 0, 0));
    }

    #[test]
    fn jittered_projection_survives_camera_restore_for_the_exact_retry_transaction() {
        let target = TargetDescription {
            width: 1920,
            height: 1080,
            format: D3DFMT_A8R8G8B8,
        };
        let restored_camera = CameraFrame {
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
        };
        let jittered_camera = restored_camera
            .with_pixel_jitter([0.5, -0.25], target.width, target.height)
            .expect("valid jittered projection");
        let projection = TemporalProjectionOverride {
            epoch: 7,
            target_surface: 0x1234,
            target,
            rendered_camera: jittered_camera,
            output_camera: restored_camera,
        };

        let retry_cameras = projection
            .cameras_for(7, 0x1234, target)
            .expect("matching retry projection");
        assert_eq!(
            retry_cameras.rendered.frustum_left,
            jittered_camera.frustum_left
        );
        assert_eq!(
            retry_cameras.output.frustum_left,
            restored_camera.frustum_left
        );
        assert_ne!(
            retry_cameras.rendered.frustum_left,
            retry_cameras.output.frustum_left
        );
        assert!(projection.cameras_for(8, 0x1234, target).is_none());
        assert!(projection.cameras_for(7, 0x5678, target).is_none());
        assert!(
            projection
                .cameras_for(
                    7,
                    0x1234,
                    TargetDescription {
                        width: 1280,
                        ..target
                    },
                )
                .is_none()
        );
    }

    #[test]
    fn skipped_pre_alpha_attempt_remains_eligible_for_complete_world_fallback() {
        let mut epoch = EpochState::default();
        record_pre_alpha_outcome(&mut epoch, AtmosphereDrawOutcome::Skipped);

        assert!(!epoch.atmosphere_complete);
        assert!(!epoch.atmosphere_drew);

        record_pre_alpha_outcome(&mut epoch, AtmosphereDrawOutcome::NoVisibleContribution);
        assert!(epoch.atmosphere_complete);
        assert!(!epoch.atmosphere_drew);

        record_pre_alpha_outcome(&mut epoch, AtmosphereDrawOutcome::ComposedWithLighting);
        assert!(epoch.atmosphere_complete);
        assert!(epoch.atmosphere_drew);
    }
}

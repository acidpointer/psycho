//! Native Fallout: New Vegas world-shadow producer and deferred consumer.
//!
//! The public crate boundary deliberately exposes one Shadows feature with an
//! exterior and an interior admission bit. Generation remains attached to the
//! engine's common shadow epoch, while consumption occurs after opaque depth
//! and before native alpha/atmosphere. No engine pointer crosses that boundary.
//!
//! # Startup ownership
//!
//! All settings atomics in this module deliberately remain zero/unpublished
//! throughout `NVSEPlugin_Load`. Do not call [`configure_runtime_options`],
//! force `PIPELINE`, or start shader preparation from plugin-load config or
//! `ScreenShaderRuntime::configure`, even though the atomic publisher itself
//! is pointer-free and lock-free. The rejected early Shadows publication
//! changed OMV's pre-Deferred footprint and reproduced the known
//! BaseObjectSwapper crash. [`install`] is the first legal publisher and is
//! called only from the DeferredInit installer. Later ImGui and Current Look
//! operations may update the same passive atomics because the deferred route
//! and worker topology already exist by then.

use core::ffi::c_void;
use std::sync::{
    LazyLock,
    atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering},
};

use anyhow::{Context, Result};
use parking_lot::Mutex;

mod contract;
mod engine;
mod math;
mod native;
mod pipeline;
mod render;
mod shaders;

#[cfg(test)]
mod contract_tests;

#[cfg(test)]
mod reference_tests;

#[cfg(test)]
mod shader_tests;

use contract::{HookAction, ShadowSettings};
use pipeline::{ReplacementResult, ShadowPipeline};

const ENABLED_BIT: u8 = 1 << 0;
const EXTERIOR_BIT: u8 = 1 << 1;
const INTERIOR_BIT: u8 = 1 << 2;
const CONTACT_BIT: u8 = 1 << 3;

static SETTINGS: AtomicU8 = AtomicU8::new(0);
static SETTINGS_REVISION: AtomicU32 = AtomicU32::new(0);
static EXTERIOR_DARKNESS: AtomicU32 = AtomicU32::new(0);
static EXTERIOR_DISTANCE: AtomicU32 = AtomicU32::new(0);
static CASCADE_SPLIT_LAMBDA: AtomicU32 = AtomicU32::new(0);
static CONTACT_DISTANCE: AtomicU32 = AtomicU32::new(0);
static CONTACT_RAY_DISTANCE: AtomicU32 = AtomicU32::new(0);
static INTERIOR_DARKNESS: AtomicU32 = AtomicU32::new(0);
static INTERIOR_SHADOWED_LIGHTS: AtomicU32 = AtomicU32::new(0);
static INTERIOR_LIGHT_RADIUS_MULTIPLIER: AtomicU32 = AtomicU32::new(0);
static INTERIOR_LIGHT_DRAW_DISTANCE: AtomicU32 = AtomicU32::new(0);
static INTERIOR_RECEIVER_BIAS: AtomicU32 = AtomicU32::new(0);
static ROUTE_READY: AtomicBool = AtomicBool::new(false);
static PIPELINE: LazyLock<Mutex<ShadowPipeline>> =
    LazyLock::new(|| Mutex::new(ShadowPipeline::default()));

/// Runtime settings for the single native Shadows feature.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct NativeShadowsSettings {
    /// Master switch for OMV shadow ownership and composition.
    pub(crate) enabled: bool,
    /// Enables the four-cascade exterior branch.
    pub(crate) exterior_enabled: bool,
    /// Enables up to twelve cube-shadowed interior point lights.
    pub(crate) interior_enabled: bool,
    /// Maximum exterior darkness.
    pub(crate) exterior_darkness: f32,
    /// Directional cascade coverage distance.
    pub(crate) exterior_distance: f32,
    /// Uniform-to-logarithmic cascade distribution.
    pub(crate) cascade_split_lambda: f32,
    /// Enables camera-stable EVSM contact refinement for exteriors.
    pub(crate) contact_shadows: bool,
    /// Maximum depth covered by contact shadows.
    pub(crate) contact_distance: f32,
    /// World-space length of the screen-depth contact ray.
    ///
    /// The field name remains schema-one compatibility data.
    pub(crate) contact_ray_distance: f32,
    /// Maximum interior darkness.
    pub(crate) interior_darkness: f32,
    /// Bounded local-light cube budget in either active location branch.
    ///
    /// The field name is schema-one compatibility data; exterior Pip-Boy and
    /// practical lights use the same replacement budget.
    pub(crate) interior_shadowed_lights: usize,
    /// Native local-light radius multiplier in either location branch.
    pub(crate) interior_light_radius_multiplier: f32,
    /// Maximum nearby local-light coverage in either location branch.
    pub(crate) interior_light_draw_distance: f32,
    /// Local-light radial receiver bias.
    pub(crate) interior_receiver_bias: f32,
}

impl NativeShadowsSettings {
    /// Apply the graphics-wide master switch without altering persisted bits.
    pub(crate) fn with_master_enabled(mut self, master_enabled: bool) -> Self {
        self.enabled &= master_enabled;
        self
    }

    fn contract(self) -> ShadowSettings {
        ShadowSettings {
            enabled: self.enabled,
            exterior_enabled: self.exterior_enabled,
            interior_enabled: self.interior_enabled,
        }
    }
}

impl From<crate::config::NativeShadowsConfig> for NativeShadowsSettings {
    fn from(value: crate::config::NativeShadowsConfig) -> Self {
        let value = value.sanitized();
        Self {
            enabled: value.enabled,
            exterior_enabled: value.exterior_enabled,
            interior_enabled: value.interior_enabled,
            exterior_darkness: value.exterior_darkness,
            exterior_distance: value.exterior_distance,
            cascade_split_lambda: value.cascade_split_lambda,
            contact_shadows: value.contact_shadows,
            contact_distance: value.contact_distance,
            contact_ray_distance: value.contact_ray_distance,
            interior_darkness: value.interior_darkness,
            interior_shadowed_lights: value.interior_shadowed_lights as usize,
            interior_light_radius_multiplier: value.interior_light_radius_multiplier,
            interior_light_draw_distance: value.interior_light_draw_distance,
            interior_receiver_bias: value.interior_receiver_bias,
        }
    }
}

impl From<NativeShadowsSettings> for crate::config::NativeShadowsConfig {
    fn from(value: NativeShadowsSettings) -> Self {
        Self {
            enabled: value.enabled,
            exterior_enabled: value.exterior_enabled,
            interior_enabled: value.interior_enabled,
            exterior_darkness: value.exterior_darkness,
            exterior_distance: value.exterior_distance,
            cascade_split_lambda: value.cascade_split_lambda,
            contact_shadows: value.contact_shadows,
            contact_distance: value.contact_distance,
            contact_ray_distance: value.contact_ray_distance,
            interior_darkness: value.interior_darkness,
            interior_shadowed_lights: value.interior_shadowed_lights as i32,
            interior_light_radius_multiplier: value.interior_light_radius_multiplier,
            interior_light_draw_distance: value.interior_light_draw_distance,
            interior_receiver_bias: value.interior_receiver_bias,
        }
    }
}

/// Exclusive next action returned to the common-hook owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommonEntryOutcome {
    /// Invoke the original native prefix; it includes the native tail.
    NativePrefix,
    /// OMV generated maps; invoke only the native tail exactly once.
    ReplacementThenTail,
    /// Production is disabled or already complete; invoke only the native tail.
    TailOnly,
}

/// Publish post-Deferred passive settings without touching D3D ownership.
///
/// The atomic transaction is suitable for menu and persistence-worker edits,
/// but startup code must not call it before `DeferredInit`. That phase rule is
/// about the complete OMV load footprint, not merely whether these stores are
/// individually thread-safe.
pub(crate) fn configure_runtime_options(settings: NativeShadowsSettings) {
    // A release-published seqlock keeps the render thread's multi-field
    // snapshot coherent without adding a lock to either startup or hooks.
    SETTINGS_REVISION.fetch_add(1, Ordering::AcqRel);
    let bits = (settings.enabled as u8) * ENABLED_BIT
        | (settings.exterior_enabled as u8) * EXTERIOR_BIT
        | (settings.interior_enabled as u8) * INTERIOR_BIT
        | (settings.contact_shadows as u8) * CONTACT_BIT;
    SETTINGS.store(bits, Ordering::Relaxed);
    EXTERIOR_DARKNESS.store(settings.exterior_darkness.to_bits(), Ordering::Relaxed);
    EXTERIOR_DISTANCE.store(settings.exterior_distance.to_bits(), Ordering::Relaxed);
    CASCADE_SPLIT_LAMBDA.store(settings.cascade_split_lambda.to_bits(), Ordering::Relaxed);
    CONTACT_DISTANCE.store(settings.contact_distance.to_bits(), Ordering::Relaxed);
    CONTACT_RAY_DISTANCE.store(settings.contact_ray_distance.to_bits(), Ordering::Relaxed);
    INTERIOR_DARKNESS.store(settings.interior_darkness.to_bits(), Ordering::Relaxed);
    INTERIOR_SHADOWED_LIGHTS.store(settings.interior_shadowed_lights as u32, Ordering::Relaxed);
    INTERIOR_LIGHT_RADIUS_MULTIPLIER.store(
        settings.interior_light_radius_multiplier.to_bits(),
        Ordering::Relaxed,
    );
    INTERIOR_LIGHT_DRAW_DISTANCE.store(
        settings.interior_light_draw_distance.to_bits(),
        Ordering::Relaxed,
    );
    INTERIOR_RECEIVER_BIAS.store(settings.interior_receiver_bias.to_bits(), Ordering::Relaxed);
    SETTINGS_REVISION.fetch_add(1, Ordering::Release);
}

/// Establish shadow ownership at xNVSE `DeferredInit`.
///
/// Engine globals are validated before the route opens. Shader compilation is
/// then prepared off-thread; until the complete bytecode family is published,
/// every common-hook invocation safely continues through the native prefix.
pub(crate) fn install(settings: NativeShadowsSettings) -> Result<()> {
    configure_runtime_options(settings);
    native::validate_contract()
        .map_err(anyhow::Error::msg)
        .context("native shadow engine contract validation failed")?;
    LazyLock::force(&PIPELINE);
    shaders::start_preparation();
    ROUTE_READY.store(true, Ordering::Release);
    log::info!(
        "[SHADOWS] Deferred route installed (master={}, exterior={}, interior={})",
        settings.enabled,
        settings.exterior_enabled,
        settings.interior_enabled,
    );
    Ok(())
}

/// Attempt replacement work and select the common hook's only legal tail path.
///
/// # Safety
///
/// Must run from the supported executable's serialized common shadow entry.
/// The ABI bridge must preserve the live receiver. Caller ancestry is not an
/// input to production: modern NVR replaces this validated common entry for
/// every caller, and OMV likewise reads only global world owners while writing
/// private map resources. Only the later pre-alpha consumer is tied to the
/// outer player-visible destination.
pub(crate) unsafe fn handle_common_entry() -> CommonEntryOutcome {
    if !ROUTE_READY.load(Ordering::Acquire) {
        return CommonEntryOutcome::NativePrefix;
    }
    let Some(scene) = (unsafe { native::current_scene() }) else {
        return CommonEntryOutcome::NativePrefix;
    };
    let settings = current_settings().with_master_enabled(crate::runtime::effects_enabled());
    let bytecode = shaders::prepared_bytecode();
    match settings
        .contract()
        .hook_action(scene.kind, true, bytecode.is_some())
    {
        HookAction::NativePrefix => CommonEntryOutcome::NativePrefix,
        HookAction::TailOnly => {
            if let Some(mut pipeline) = PIPELINE.try_lock() {
                pipeline.invalidate_publication();
            }
            CommonEntryOutcome::TailOnly
        }
        HookAction::ReplacementThenTail => {
            let Some(bytecode) = bytecode else {
                // `hook_action` admits this branch only with complete
                // bytecode. Keep the native fallback explicit if that pure
                // contract ever changes.
                return CommonEntryOutcome::NativePrefix;
            };
            let Some(mut pipeline) = PIPELINE.try_lock() else {
                return CommonEntryOutcome::NativePrefix;
            };
            if pipeline.has_current_publication(scene.kind) {
                // Some engine paths can reach the common entry more than once
                // before Present advances the epoch. The first complete
                // publication is immutable; repeating 4 cascades or 72 cube
                // faces would add cost without changing its global inputs.
                return CommonEntryOutcome::TailOnly;
            }
            match unsafe { pipeline.produce(scene, &bytecode, settings) } {
                ReplacementResult::Produced => CommonEntryOutcome::ReplacementThenTail,
                ReplacementResult::FallbackNative => CommonEntryOutcome::NativePrefix,
            }
        }
    }
}

/// Return whether resident world hooks must expose the pre-alpha consumer.
pub(crate) fn needs_scene_hooks() -> bool {
    needs_pre_alpha()
}

/// Return whether the current passive settings can consume a shadow map.
pub(crate) fn needs_pre_alpha() -> bool {
    if !ROUTE_READY.load(Ordering::Acquire) || !crate::runtime::effects_enabled() {
        return false;
    }
    let bits = SETTINGS.load(Ordering::Acquire);
    bits & ENABLED_BIT != 0 && bits & (EXTERIOR_BIT | INTERIOR_BIT) != 0
}

/// Resolve the sun vector shared by directional shadows and atmosphere.
///
/// NVR deliberately stabilizes the sky direction before building cascades.
/// Downstream shafts and volumetric scattering must use the same vector or
/// their apparent light source separates from the cast shadow. A busy or
/// absent shadow publication conservatively retains the native direction.
pub(crate) fn directional_sun_direction(native: [f32; 3]) -> [f32; 3] {
    PIPELINE
        .try_lock()
        .and_then(|pipeline| pipeline.directional_sun_direction())
        .unwrap_or(native)
}

/// Composite the newest compatible shadow publication after opaque geometry.
///
/// # Safety
///
/// `device_ptr` must own the live main-world RT0 at the engine's validated
/// pre-alpha boundary. The consumer resolves the matching world depth before
/// drawing and never falls forward to a later image-space phase.
pub(crate) unsafe fn apply_before_alpha(device_ptr: *mut c_void) {
    let settings = current_settings().with_master_enabled(crate::runtime::effects_enabled());
    if !ROUTE_READY.load(Ordering::Acquire) || !settings.enabled {
        return;
    }
    let Some(mut pipeline) = PIPELINE.try_lock() else {
        return;
    };
    if let Err(error) = unsafe { pipeline.consume_before_alpha(device_ptr, settings) } {
        log::warn!("[SHADOWS] Pre-alpha composition failed: {error}");
        pipeline.invalidate_publication();
    }
}

/// Release default-pool shadow resources before native device recreation.
///
/// A busy render transaction returns `false`, causing the engine's existing
/// Recreate detour to retry instead of resetting under live COM resources.
pub(crate) fn reset_runtime_state() -> bool {
    if !ROUTE_READY.load(Ordering::Acquire) {
        return true;
    }
    let Some(mut pipeline) = PIPELINE.try_lock() else {
        return false;
    };
    pipeline.release();
    true
}

fn try_current_settings() -> Option<NativeShadowsSettings> {
    let before = SETTINGS_REVISION.load(Ordering::Acquire);
    if before == 0 || before & 1 != 0 {
        return None;
    }
    let bits = SETTINGS.load(Ordering::Relaxed);
    let settings = NativeShadowsSettings {
        enabled: bits & ENABLED_BIT != 0,
        exterior_enabled: bits & EXTERIOR_BIT != 0,
        interior_enabled: bits & INTERIOR_BIT != 0,
        exterior_darkness: f32::from_bits(EXTERIOR_DARKNESS.load(Ordering::Relaxed)),
        exterior_distance: f32::from_bits(EXTERIOR_DISTANCE.load(Ordering::Relaxed)),
        cascade_split_lambda: f32::from_bits(CASCADE_SPLIT_LAMBDA.load(Ordering::Relaxed)),
        contact_shadows: bits & CONTACT_BIT != 0,
        contact_distance: f32::from_bits(CONTACT_DISTANCE.load(Ordering::Relaxed)),
        contact_ray_distance: f32::from_bits(CONTACT_RAY_DISTANCE.load(Ordering::Relaxed)),
        interior_darkness: f32::from_bits(INTERIOR_DARKNESS.load(Ordering::Relaxed)),
        interior_shadowed_lights: INTERIOR_SHADOWED_LIGHTS.load(Ordering::Relaxed) as usize,
        interior_light_radius_multiplier: f32::from_bits(
            INTERIOR_LIGHT_RADIUS_MULTIPLIER.load(Ordering::Relaxed),
        ),
        interior_light_draw_distance: f32::from_bits(
            INTERIOR_LIGHT_DRAW_DISTANCE.load(Ordering::Relaxed),
        ),
        interior_receiver_bias: f32::from_bits(INTERIOR_RECEIVER_BIAS.load(Ordering::Relaxed)),
    };
    (SETTINGS_REVISION.load(Ordering::Acquire) == before).then_some(settings)
}

fn current_settings() -> NativeShadowsSettings {
    for _ in 0..3 {
        if let Some(settings) = try_current_settings() {
            return settings;
        }
    }
    // A concurrent menu publication is transient. Returning the safe disabled
    // state makes the current hook use its native fallback without blocking.
    NativeShadowsSettings::from(crate::config::NativeShadowsConfig {
        enabled: false,
        ..crate::config::NativeShadowsConfig::default()
    })
}

/// Return a coherent persisted Shadows value for the menu or I/O worker.
///
/// Unlike a render hook, these callers must not substitute a disabled value
/// during a concurrent menu publication because doing so could overwrite the
/// user's durable settings. The single writer completes a fixed set of atomic
/// stores, so this brief spin cannot wait on a lock or D3D operation.
pub(crate) fn runtime_config() -> crate::config::NativeShadowsConfig {
    if SETTINGS_REVISION.load(Ordering::Acquire) == 0 {
        return crate::config::NativeShadowsConfig::default();
    }
    loop {
        if let Some(settings) = try_current_settings() {
            return settings.into();
        }
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod startup_safety_tests {
    use super::{
        NativeShadowsSettings, configure_runtime_options, current_settings, runtime_config,
    };

    #[test]
    fn menu_values_round_trip_through_the_render_thread_seqlock() {
        let expected = NativeShadowsSettings {
            enabled: true,
            exterior_enabled: false,
            interior_enabled: true,
            exterior_darkness: 0.42,
            exterior_distance: 7_654.0,
            cascade_split_lambda: 0.73,
            contact_shadows: false,
            contact_distance: 123_456.0,
            contact_ray_distance: 1_234.0,
            interior_darkness: 0.57,
            interior_shadowed_lights: 7,
            interior_light_radius_multiplier: 1.75,
            interior_light_draw_distance: 6_543.0,
            interior_receiver_bias: 0.023,
        };

        configure_runtime_options(expected);
        assert_eq!(current_settings(), expected);
        assert_eq!(runtime_config(), expected.into());
        assert!(!current_settings().with_master_enabled(false).enabled);
        assert_eq!(runtime_config(), expected.into());

        // Leave process-global state at the shipped defaults for any later
        // test that exercises the handler rather than this publication unit.
        configure_runtime_options(NativeShadowsSettings::from(
            crate::config::NativeShadowsConfig::default(),
        ));
    }

    #[test]
    fn passive_configuration_is_atomic_only() {
        let source = include_str!("mod.rs");
        let configure = source
            .split_once("pub(crate) fn configure_runtime_options(")
            .and_then(|(_, tail)| tail.split_once("/// Establish shadow ownership"))
            .map(|(body, _)| body)
            .expect("passive shadow configuration body");
        assert!(configure.contains("SETTINGS.store(bits, Ordering::Relaxed)"));
        assert!(configure.contains("SETTINGS_REVISION.fetch_add(1, Ordering::AcqRel)"));
        assert!(configure.contains("SETTINGS_REVISION.fetch_add(1, Ordering::Release)"));
        for forbidden in [
            "LazyLock::force",
            "PIPELINE.lock",
            "PIPELINE.try_lock",
            "start_preparation",
            "validate_contract",
            "d3d_device",
        ] {
            assert!(
                !configure.contains(forbidden),
                "pre-deferred action: {forbidden}"
            );
        }

        let install = source
            .split_once("pub(crate) fn install(")
            .and_then(|(_, tail)| tail.split_once("/// Attempt replacement work"))
            .map(|(body, _)| body)
            .expect("DeferredInit shadow installation body");
        let validate = install
            .find("native::validate_contract")
            .expect("engine validation");
        let pipeline = install
            .find("LazyLock::force(&PIPELINE)")
            .expect("pipeline owner");
        let compile = install
            .find("shaders::start_preparation()")
            .expect("compile start");
        let route = install
            .find("ROUTE_READY.store(true")
            .expect("route publication");
        assert!(validate < pipeline && pipeline < compile && compile < route);
    }
}

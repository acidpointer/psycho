//! Native Fallout: New Vegas world-shadow producer and deferred consumer.
//!
//! The public crate boundary deliberately exposes one Shadows feature with an
//! exterior and an interior admission bit. Generation remains attached to the
//! engine's common shadow epoch, while consumption occurs at scene-pre after a
//! coherent depth snapshot exists. No engine pointer crosses that boundary.

use core::ffi::c_void;
use std::sync::{
    LazyLock,
    atomic::{AtomicBool, AtomicU8, Ordering},
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
mod shader_tests;

use contract::{HookAction, InvocationContext, ShadowSettings};
use pipeline::{ReplacementResult, ShadowPipeline};

const ENABLED_BIT: u8 = 1 << 0;
const EXTERIOR_BIT: u8 = 1 << 1;
const INTERIOR_BIT: u8 = 1 << 2;

static SETTINGS: AtomicU8 = AtomicU8::new(0);
static ROUTE_READY: AtomicBool = AtomicBool::new(false);
static PIPELINE: LazyLock<Mutex<ShadowPipeline>> =
    LazyLock::new(|| Mutex::new(ShadowPipeline::default()));

/// Runtime settings for the single native Shadows feature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeShadowsSettings {
    /// Master switch for OMV shadow ownership and composition.
    pub(crate) enabled: bool,
    /// Enables the four-cascade exterior branch.
    pub(crate) exterior_enabled: bool,
    /// Enables twelve cube-shadowed plus twelve tracked interior point lights.
    pub(crate) interior_enabled: bool,
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
        Self {
            enabled: value.enabled,
            exterior_enabled: value.exterior_enabled,
            interior_enabled: value.interior_enabled,
        }
    }
}

/// Proven caller category supplied by the common-hook ABI bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommonInvocationContext {
    /// Normal player-visible world rendering.
    Main,
    /// Engine-owned offscreen or special rendering.
    Special,
    /// Dedicated high-resolution screenshot rendering.
    Screenshot,
    /// A caller outside the documented frame-pointer chain.
    Unknown,
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

/// Publish passive settings without touching deferred graphics ownership.
///
/// This function is intentionally safe during `NVSEPlugin_Load`: it performs
/// one atomic store and does not initialize the pipeline `LazyLock`, inspect
/// the engine, compile shaders, or allocate D3D resources.
pub(crate) fn configure_runtime_options(settings: NativeShadowsSettings) {
    let bits = (settings.enabled as u8) * ENABLED_BIT
        | (settings.exterior_enabled as u8) * EXTERIOR_BIT
        | (settings.interior_enabled as u8) * INTERIOR_BIT;
    SETTINGS.store(bits, Ordering::Release);
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
/// The ABI bridge must have preserved the live branch receiver and classified
/// the caller using the documented EBP chain.
pub(crate) unsafe fn handle_common_entry(context: CommonInvocationContext) -> CommonEntryOutcome {
    if !ROUTE_READY.load(Ordering::Acquire) || context == CommonInvocationContext::Unknown {
        return CommonEntryOutcome::NativePrefix;
    }
    let Some(scene) = (unsafe { native::current_scene() }) else {
        return CommonEntryOutcome::NativePrefix;
    };
    let settings = current_settings().contract();
    let bytecode = shaders::prepared_bytecode();
    match settings.hook_action(scene.kind, true, bytecode.is_some()) {
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
            if context == CommonInvocationContext::Main
                && pipeline.has_current_main_publication(scene.kind)
            {
                // Some engine paths can reach the common entry more than once
                // before Present advances the epoch. The first complete main
                // publication is immutable; repeating 4 cascades or 72 cube
                // faces would add cost without changing the consumer input.
                return CommonEntryOutcome::TailOnly;
            }
            let context = match context {
                CommonInvocationContext::Main => InvocationContext::Main,
                CommonInvocationContext::Special => InvocationContext::Special,
                CommonInvocationContext::Screenshot => InvocationContext::Screenshot,
                CommonInvocationContext::Unknown => return CommonEntryOutcome::NativePrefix,
            };
            match unsafe { pipeline.produce(scene, context, &bytecode) } {
                ReplacementResult::Produced => CommonEntryOutcome::ReplacementThenTail,
                ReplacementResult::FallbackNative => CommonEntryOutcome::NativePrefix,
            }
        }
    }
}

/// Composite a same-epoch shadow publication before other scene-pre effects.
///
/// # Safety
///
/// `device_ptr` and `source_rendered_texture` must be the live values supplied
/// by the outer FNV image-space callback.
pub(crate) unsafe fn apply_scene_pre(
    device_ptr: *mut c_void,
    source_rendered_texture: *mut c_void,
) {
    if !ROUTE_READY.load(Ordering::Acquire) || !current_settings().enabled {
        return;
    }
    let Some(mut pipeline) = PIPELINE.try_lock() else {
        return;
    };
    if let Err(error) = unsafe { pipeline.consume_scene_pre(device_ptr, source_rendered_texture) } {
        log::warn!("[SHADOWS] Scene-pre composition failed: {error}");
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

fn current_settings() -> NativeShadowsSettings {
    let bits = SETTINGS.load(Ordering::Acquire);
    NativeShadowsSettings {
        enabled: bits & ENABLED_BIT != 0,
        exterior_enabled: bits & EXTERIOR_BIT != 0,
        interior_enabled: bits & INTERIOR_BIT != 0,
    }
}

#[cfg(test)]
mod startup_safety_tests {
    #[test]
    fn pre_deferred_configuration_is_atomic_only() {
        let source = include_str!("mod.rs");
        let configure = source
            .split_once("pub(crate) fn configure_runtime_options(")
            .and_then(|(_, tail)| tail.split_once("/// Establish shadow ownership"))
            .map(|(body, _)| body)
            .expect("passive shadow configuration body");
        assert!(configure.contains("SETTINGS.store(bits, Ordering::Release)"));
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

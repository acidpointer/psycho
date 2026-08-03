//! xNVSE-owned graphics startup and DeferredInit hook publication.
//!
//! `NVSEPlugin_Load` performs configuration and process-owned worker
//! preparation only. Native-PBR prewarm may read embedded source and its
//! reconstructible cache there, but it cannot inspect the engine or D3D device.
//! Device inspection, initial depth-producer selection, world-pipeline
//! publication, and executable hook installation occur at `DeferredInit`,
//! after data loading and outside render callbacks. Optional depth capability
//! may select a safe session fallback, but it never gates unrelated OMV hooks.
//! Deferred installation is guarded transactionally: concurrent calls do not
//! overlap, a failed attempt is retryable, and only full success is published
//! as installed.

use std::sync::{
    LazyLock,
    atomic::{AtomicBool, AtomicU8, Ordering},
};

use anyhow::{Context, Result};
use libpsycho::logger::Logger;
use parking_lot::Mutex;

const LOG_FILE: &str = "./omv-latest.log";

#[derive(Clone, Copy)]
struct DeferredHookSettings {
    native_pbr: crate::effects::pbr::NativePbrSettings,
    native_sky: crate::effects::sky::NativeSkySettings,
    depth_provider: crate::backend::DepthProvider,
}

static DEFERRED_HOOK_SETTINGS: LazyLock<Mutex<Option<DeferredHookSettings>>> =
    LazyLock::new(|| Mutex::new(None));
const DEFERRED_INSTALL_NOT_STARTED: u8 = 0;
const DEFERRED_INSTALL_IN_PROGRESS: u8 = 1;
const DEFERRED_INSTALL_COMPLETE: u8 = 2;

static DEFERRED_INSTALL_STATE: AtomicU8 = AtomicU8::new(DEFERRED_INSTALL_NOT_STARTED);
static COMPAT_REPORT_LOGGED: AtomicBool = AtomicBool::new(false);

struct DeferredInstallAttempt<'a> {
    state: &'a AtomicU8,
    completed: bool,
}

impl DeferredInstallAttempt<'_> {
    fn complete(mut self) {
        self.state
            .store(DEFERRED_INSTALL_COMPLETE, Ordering::Release);
        self.completed = true;
    }
}

impl Drop for DeferredInstallAttempt<'_> {
    fn drop(&mut self) {
        if !self.completed {
            // Every DeferredInit installer is idempotent or re-enables its
            // prepared hook. Resetting the gate permits recovery from a
            // transient mailbox, device, or worker-spawn failure without ever
            // publishing a partial attempt as complete.
            self.state
                .store(DEFERRED_INSTALL_NOT_STARTED, Ordering::Release);
        }
    }
}

fn begin_deferred_install(
    state: &AtomicU8,
) -> Result<Option<DeferredInstallAttempt<'_>>, &'static str> {
    match state.compare_exchange(
        DEFERRED_INSTALL_NOT_STARTED,
        DEFERRED_INSTALL_IN_PROGRESS,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => Ok(Some(DeferredInstallAttempt {
            state,
            completed: false,
        })),
        Err(DEFERRED_INSTALL_COMPLETE) => Ok(None),
        Err(_) => Err("deferred graphics hook installation is already in progress"),
    }
}

/// Stage configuration and process-owned workers during `NVSEPlugin_Load`.
///
/// This boundary must not inspect engine graphics objects, publish focused
/// world state, or install hooks. [`install_deferred_hooks`] owns those later
/// transitions after xNVSE reports `DeferredInit`.
pub(crate) fn initialize_for_nvse() -> Result<()> {
    let cfg = crate::config::load_config();

    initialize_logging(&cfg.diagnostics)?;
    log::info!("[INIT] Oh My Vegas graphics initialized through xNVSE");
    log::info!(
        "[INIT] OMV build unix={} target={} profile={}",
        option_env!("OMV_BUILD_UNIX").unwrap_or("unknown"),
        option_env!("OMV_BUILD_TARGET").unwrap_or("unknown"),
        option_env!("OMV_BUILD_PROFILE").unwrap_or("unknown")
    );
    log::info!(
        "[INIT] OMV source commit={} branch={} tag={} dirty={}",
        option_env!("OMV_GIT_COMMIT").unwrap_or("unknown"),
        option_env!("OMV_GIT_BRANCH").unwrap_or("unknown"),
        option_env!("OMV_GIT_TAG")
            .filter(|tag| !tag.is_empty())
            .unwrap_or("<none>"),
        option_env!("OMV_GIT_DIRTY").unwrap_or("unknown")
    );
    log::info!(
        "[CONFIG] Working path '{}'; distribution fallback '{}' (read-only startup)",
        crate::config::CONFIG_PATH,
        crate::config::DEFAULT_CONFIG_PATH
    );
    crate::shaders::start_shader_cache_maintenance();

    let menu_config = crate::config::GraphicsMenuConfig::from(cfg);
    let native_pbr = crate::effects::pbr::NativePbrSettings::from(cfg.graphics.native_pbr)
        .with_master_enabled(cfg.graphics.screen_space_shaders);
    let native_sky = crate::effects::sky::NativeSkySettings::from(cfg.graphics.native_sky)
        .with_master_enabled(cfg.graphics.screen_space_shaders);

    if !cfg.graphics.screen_space_shaders {
        log::info!("[SHADERS] OMV effects disabled by the master config switch");
    }

    let depth_provider = crate::backend::DepthProvider::from(cfg.graphics.depth_provider);
    log::info!(
        "[CONFIG] Requested depth provider: {}",
        depth_provider.label()
    );
    crate::runtime::configure(crate::runtime::RuntimeSettings {
        menu_config,
        depth_provider,
        menu_toggle_key: cfg.graphics.menu_toggle_key,
        shader_scan_interval_ms: cfg.graphics.shader_scan_interval_ms,
    });

    log::info!(
        "[SHADERS] Watching screen-space shaders in '{}'",
        crate::shaders::SHADER_DIR
    );
    log::info!("[IMGUI] Shader menu enabled");

    *DEFERRED_HOOK_SETTINGS.lock() = Some(DeferredHookSettings {
        native_pbr,
        native_sky,
        depth_provider,
    });
    // Start only after the deferred settings handoff is complete. If the
    // worker finishes immediately, DeferredInit can adopt its bytecode without
    // changing the proven first-publication or hook-install ordering.
    crate::effects::pbr::start_cpu_preparation(native_pbr);

    Ok(())
}

/// Record compatibility state after xNVSE completes normal plugin loading.
pub(crate) fn observe_post_load() {
    log_compatibility_report(crate::compat::GraphicsCompatibility::detect());
}

/// Publish initial graphics ownership and install hooks at `DeferredInit`.
///
/// Installation is transactional and idempotent: a completed attempt latches
/// success, while a partial failure releases the gate for a later retry.
pub(crate) fn install_deferred_hooks() -> Result<()> {
    let Some(install_attempt) =
        begin_deferred_install(&DEFERRED_INSTALL_STATE).map_err(anyhow::Error::msg)?
    else {
        log::info!("[INIT] Deferred graphics hooks already installed");
        return Ok(());
    };

    let result = install_deferred_hooks_once();
    if result.is_err() {
        // Inline or device hooks may already be resident when a later step
        // fails. Publishing the no-depth state makes those callbacks inert and
        // ensures an external producer is never suppressed by a partial
        // startup attempt. The transactional gate remains retryable.
        crate::backend::abandon_initial_depth_provider();
    }
    result?;
    install_attempt.complete();
    log::info!("[INIT] Deferred OMV graphics hooks initialized");

    Ok(())
}

fn install_deferred_hooks_once() -> Result<()> {
    let settings = DEFERRED_HOOK_SETTINGS
        .lock()
        .as_ref()
        .copied()
        .context("graphics startup settings were not initialized")?;
    let compatibility = crate::compat::GraphicsCompatibility::detect();
    log_compatibility_report(compatibility);

    let depth_activation = crate::backend::initialize_depth_provider(settings.depth_provider);
    let menu_config = crate::runtime::apply_initial_depth_activation(depth_activation);
    crate::backend::startup_log(depth_activation.active);

    // This must remain the first world-pipeline config publication. Publishing
    // from NVSEPlugin_Load caused the 2026-07-18 data-loading crash.
    if !crate::fnv_world_pipeline::publish_config(menu_config) {
        anyhow::bail!("world-effects config owner was busy before hook installation");
    }
    log::info!("[FNV WORLD] Initial config published at DeferredInit");

    crate::effects::pbr::configure_terrain_contract(compatibility.has_vpt_terrain_contract());
    crate::effects::pbr::install(settings.native_pbr)?;
    crate::effects::sky::install(settings.native_sky)?;
    crate::hooks::install_engine_hooks()
        .context("could not establish engine-owned render lifecycle hooks")?;

    crate::fnv_local_lights::install_hooks();
    // Initialize every scene hook while DeferredInit is quiescent so later
    // DisplayScene-boundary transitions can restore or reattach the proven
    // entry bytes without allocating a new trampoline.
    crate::fnv_render::install_scene_boundary_hook();
    crate::fnv_render::reconcile_depth_stage_hooks()
        .context("could not establish configured depth-stage hook ownership")?;
    Ok(())
}

#[cfg(test)]
mod deferred_install_tests {
    use super::*;

    #[test]
    fn failed_attempt_releases_the_gate_for_retry() {
        let state = AtomicU8::new(DEFERRED_INSTALL_NOT_STARTED);
        let attempt = begin_deferred_install(&state)
            .expect("first attempt")
            .expect("new attempt guard");
        assert_eq!(state.load(Ordering::Acquire), DEFERRED_INSTALL_IN_PROGRESS);
        drop(attempt);
        assert_eq!(state.load(Ordering::Acquire), DEFERRED_INSTALL_NOT_STARTED);
        assert!(begin_deferred_install(&state).expect("retry").is_some());
    }

    #[test]
    fn only_completed_attempts_latch_success() {
        let state = AtomicU8::new(DEFERRED_INSTALL_NOT_STARTED);
        begin_deferred_install(&state)
            .expect("first attempt")
            .expect("new attempt guard")
            .complete();
        assert_eq!(state.load(Ordering::Acquire), DEFERRED_INSTALL_COMPLETE);
        assert!(begin_deferred_install(&state).expect("repeat").is_none());
    }

    #[test]
    fn early_pbr_preparation_cannot_publish_or_install_graphics_state() {
        let source = include_str!("startup.rs");
        let initialize = source
            .split_once("pub(crate) fn initialize_for_nvse()")
            .and_then(|(_, tail)| tail.split_once("pub(crate) fn observe_post_load()"))
            .map(|(body, _)| body)
            .expect("NVSE initialization body");
        let staged = initialize
            .find("*DEFERRED_HOOK_SETTINGS.lock()")
            .expect("deferred settings handoff");
        let prewarm = initialize
            .find("pbr::start_cpu_preparation(native_pbr)")
            .expect("early PBR prewarm");
        assert!(staged < prewarm);
        assert!(!initialize.contains("fnv_world_pipeline::publish_config"));
        assert!(!initialize.contains("pbr::install("));

        let deferred = source
            .split_once("fn install_deferred_hooks_once()")
            .map(|(_, body)| body)
            .expect("DeferredInit installation body");
        assert!(deferred.contains("fnv_world_pipeline::publish_config(menu_config)"));
        assert!(deferred.contains("pbr::install(settings.native_pbr)"));
    }
}

fn log_compatibility_report(compatibility: crate::compat::GraphicsCompatibility) {
    if COMPAT_REPORT_LOGGED.swap(true, Ordering::AcqRel) {
        return;
    }

    compatibility.log_report();
}

fn initialize_logging(diagnostics: &crate::config::DiagnosticsConfig) -> Result<()> {
    let log_level = if diagnostics.debug_log {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    Logger::new()
        .with_file_rotating(LOG_FILE)
        .with_level(log_level)
        .with_module_level("libpsycho::os::windows::memory", log::LevelFilter::Warn)
        .init()
        .map_err(|err| anyhow::anyhow!("logger init failed: {:?}", err))?;

    Logger::start_deferred();
    Ok(())
}

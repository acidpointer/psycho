//! Graphics module startup.

use std::sync::{
    LazyLock,
    atomic::{AtomicBool, Ordering},
};

use anyhow::{Context, Result};
use libpsycho::logger::Logger;
use parking_lot::Mutex;

const LOG_FILE: &str = "./omv-latest.log";

#[derive(Clone, Copy)]
struct DeferredHookSettings {
    menu_config: crate::config::GraphicsMenuConfig,
    native_pbr: crate::effects::pbr::NativePbrSettings,
    native_sky: crate::effects::sky::NativeSkySettings,
    depth_provider: crate::backend::DepthProvider,
}

static DEFERRED_HOOK_SETTINGS: LazyLock<Mutex<Option<DeferredHookSettings>>> =
    LazyLock::new(|| Mutex::new(None));
static DEFERRED_HOOKS_INSTALLED: AtomicBool = AtomicBool::new(false);
static COMPAT_REPORT_LOGGED: AtomicBool = AtomicBool::new(false);

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

    let depth_provider = cfg.graphics.depth_provider.into();
    crate::backend::startup_log(depth_provider);
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
        menu_config,
        native_pbr,
        native_sky,
        depth_provider,
    });

    Ok(())
}

pub(crate) fn observe_post_load() {
    log_compatibility_report(crate::compat::GraphicsCompatibility::detect());
}

pub(crate) fn install_deferred_hooks() -> Result<()> {
    if DEFERRED_HOOKS_INSTALLED.swap(true, Ordering::AcqRel) {
        log::info!("[INIT] Deferred graphics hooks already installed");
        return Ok(());
    }

    let settings = DEFERRED_HOOK_SETTINGS
        .lock()
        .as_ref()
        .copied()
        .context("graphics startup settings were not initialized")?;
    let compatibility = crate::compat::GraphicsCompatibility::detect();
    log_compatibility_report(compatibility);

    crate::backend::initialize_depth_provider(settings.depth_provider)
        .map_err(|reason| anyhow::anyhow!("configured depth producer is unavailable: {reason}"))?;

    // This must remain the first world-pipeline config publication. Publishing
    // from NVSEPlugin_Load caused the 2026-07-18 data-loading crash.
    if !crate::fnv_world_pipeline::publish_config(settings.menu_config) {
        anyhow::bail!("world-effects config owner was busy before hook installation");
    }
    log::info!("[FNV WORLD] Initial config published at DeferredInit");

    crate::effects::pbr::configure_terrain_contract(compatibility.has_vpt_terrain_contract());
    crate::effects::pbr::install(settings.native_pbr)?;
    crate::effects::sky::install(settings.native_sky)?;

    crate::fnv_local_lights::install_hooks();
    // Initialize every scene hook while DeferredInit is quiescent so later
    // Present-boundary transitions can restore or reattach the already-proven
    // entry bytes without allocating a new trampoline.
    crate::fnv_render::install_scene_boundary_hook();
    crate::fnv_render::reconcile_depth_stage_hooks()
        .context("could not establish configured depth-stage hook ownership")?;
    if crate::backend::needs_shared_pre_alpha_depth() {
        if !crate::fnv_render::shared_depth_service_ready() {
            // Some inline hooks may already be resident. Publish the inactive
            // provider before returning so a partial startup cannot add OMV
            // copies while Depth Resolve remains physically active.
            crate::backend::abandon_initial_depth_provider();
            anyhow::bail!("shared-depth scene boundaries could not be installed");
        }
        // Exclusive ownership must be physical before any scene callback can
        // issue OMV's replacement capture. An asynchronous hook-install
        // window would briefly allow both producers on the same NVIDIA frame.
        if let Err(err) = crate::hooks::install_current_device_hooks() {
            crate::backend::abandon_initial_depth_provider();
            return Err(err).context("could not establish exclusive RESZ ownership");
        }
    }

    crate::hooks::start_install_worker()?;
    log::info!("[INIT] Deferred OMV graphics hooks initialized");

    Ok(())
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

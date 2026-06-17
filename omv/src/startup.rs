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
    native_pbr: crate::effects::pbr::NativePbrSettings,
    screen_space_shaders: bool,
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
        "[CONFIG] Loaded '{}' (read-only)",
        crate::config::CONFIG_PATH
    );

    let menu_config = crate::config::GraphicsMenuConfig::from(cfg);
    let native_pbr = cfg.graphics.native_pbr.into();

    if !cfg.graphics.screen_space_shaders {
        log::info!("[SHADERS] Screen-space shader rendering disabled by config");
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
        native_pbr,
        screen_space_shaders: cfg.graphics.screen_space_shaders,
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

    crate::effects::pbr::configure_terrain_contract(compatibility.has_vpt_terrain_contract());
    crate::effects::pbr::install(settings.native_pbr)?;

    if settings.screen_space_shaders
        && settings.depth_provider != crate::backend::DepthProvider::None
    {
        crate::fnv_render::install_scene_boundary_hook();
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

//! Graphics module startup.

use anyhow::Result;
use libpsycho::logger::Logger;

const LOG_FILE: &str = "./psycho-graphics-latest.log";

pub(crate) fn initialize() -> Result<()> {
    let cfg = crate::config::load_config();

    initialize_logging(&cfg.diagnostics)?;
    log::info!("[INIT] Graphics module initialized");
    log::info!(
        "[CONFIG] Loaded '{}' (read-only)",
        crate::config::CONFIG_PATH
    );

    let menu_config = crate::config::GraphicsMenuConfig::from(cfg);
    crate::pbr::install(crate::pbr::NativePbrSettings {
        enabled: cfg.graphics.native_pbr.enabled,
        debug_log_draws: cfg.graphics.native_pbr.debug_log_draws,
        roughness_scale: cfg.graphics.native_pbr.roughness_scale,
        light_scale: cfg.graphics.native_pbr.light_scale,
        ambient_scale: cfg.graphics.native_pbr.ambient_scale,
        albedo_saturation: cfg.graphics.native_pbr.albedo_saturation,
    })?;

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
    if depth_provider != crate::backend::DepthProvider::None {
        crate::fnv_render::install_scene_boundary_hook();
    }

    log::info!(
        "[SHADERS] Watching screen-space shaders in '{}'",
        crate::shaders::SHADER_DIR
    );
    log::info!("[IMGUI] Shader menu enabled");
    crate::hooks::start_install_worker()?;

    Ok(())
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

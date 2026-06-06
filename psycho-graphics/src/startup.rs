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

    if !cfg.graphics.screen_space_shaders {
        log::info!("[SHADERS] Screen-space shaders disabled by config");
        return Ok(());
    }

    let depth_provider = cfg.graphics.depth_provider.into();
    crate::backend::startup_log(depth_provider);
    crate::runtime::configure(crate::runtime::RuntimeSettings {
        depth_provider,
        imgui_menu: cfg.graphics.imgui_menu,
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
    log::info!(
        "[IMGUI] Shader menu {}",
        if cfg.graphics.imgui_menu {
            "enabled"
        } else {
            "disabled"
        }
    );
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

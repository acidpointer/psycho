//! Core startup sequence for `psycho_engine_fixes.dll`.
//!
//! The loader calls into `entry.rs`; this module performs the actual engine
//! setup after the DLL is safely outside loader-lock callbacks.

use shadow_rs::shadow;

use crate::{
    config::{DiagnosticsConfig, MemoryConfig, PerformanceConfig, load_config},
    mods::{
        display::install_display_hooks,
        heap_replacer::{
            AllocatorMode, decide_mode, initialize_mimalloc, install_gheap_hooks,
            install_gheap_initialize, install_sheap_hooks, install_sheap_initialize,
        },
        perf::{install_rng_hook, mark_init_start},
        zlib::install_zlib_hooks,
    },
};
use libpsycho::{
    common::exe_version::ExeVersion, logger::Logger, os::windows::winapi::alloc_console,
};

shadow!(build_info);

const FNV_RUNTIME_VERSION_1_4_0_525: u32 = 0x0400_20D0;

/// Run every core startup step exactly once.
pub(crate) fn initialize() -> anyhow::Result<()> {
    let cfg = load_config();

    initialize_logging(&cfg.diagnostics)?;
    mark_init_start();

    log::info!("[INIT] Engine fixes startup");

    initialize_diagnostics(&cfg.diagnostics)?;
    initialize_memory(&cfg.memory)?;
    install_runtime_hooks(&cfg.performance)?;

    log_runtime();
    log_build_info();
    log::info!("[INIT] Engine fixes initialized");

    Ok(())
}

fn initialize_logging(diagnostics: &DiagnosticsConfig) -> anyhow::Result<()> {
    let log_level = if diagnostics.debug_log {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    Logger::new()
        .with_file_rotating("./psycho-engine-fixes-latest.log")
        .with_level(log_level)
        .init()
        .map_err(|err| anyhow::anyhow!("logger init failed: {:?}", err))?;

    Logger::start_deferred();
    Ok(())
}

fn initialize_diagnostics(diagnostics: &DiagnosticsConfig) -> anyhow::Result<()> {
    if diagnostics.console {
        alloc_console()?;
    }

    Ok(())
}

fn initialize_memory(memory: &MemoryConfig) -> anyhow::Result<()> {
    match decide_mode(memory) {
        AllocatorMode::GheapAndScrapHeap => initialize_gheap_and_scrap_heap(),
        AllocatorMode::ScrapHeap => initialize_scrap_heap(),
        AllocatorMode::Disabled => {
            log::info!("[MEMORY] Heap allocator replacement disabled");
            Ok(())
        }
    }
}

fn initialize_gheap_and_scrap_heap() -> anyhow::Result<()> {
    // Mimalloc handles CRT allocations. Game objects stay in gheap/scrap_heap.
    initialize_mimalloc();

    install_gheap_initialize()?;
    install_sheap_initialize()?;
    install_gheap_hooks()?;
    install_sheap_hooks()?;

    Ok(())
}

fn initialize_scrap_heap() -> anyhow::Result<()> {
    initialize_mimalloc();

    install_sheap_initialize()?;
    install_sheap_hooks()?;

    Ok(())
}

fn install_runtime_hooks(performance: &PerformanceConfig) -> anyhow::Result<()> {
    if performance.rng {
        install_rng_hook()?;
    }

    if performance.zlib {
        install_zlib_hooks(false)?;
    }

    if performance.display_tweaks
        && let Err(err) = install_display_hooks()
    {
        log::warn!("[DISPLAY] Alt-tab fix disabled: {}", err);
    }

    Ok(())
}

fn log_runtime() {
    log::info!(
        "Runtime {}",
        ExeVersion::from_u32(FNV_RUNTIME_VERSION_1_4_0_525)
    );
}

fn log_build_info() {
    log::info!("========================================================");
    log::info!("");
    log::info!("   P S Y C H O");
    log::info!("");
    log::info!("========================================================");
    log::info!("        Commit: {}", build_info::COMMIT_HASH);
    log::info!("        Branch: {}", build_info::BRANCH);
    log::info!("    Build date: {}", build_info::BUILD_TIME);
    log::info!("  Rust version: {}", build_info::RUST_VERSION);
    log::info!("  Rust channel: {}", build_info::RUST_CHANNEL);
    log::info!("  Build target: {}", build_info::BUILD_TARGET);
    log::info!("      Build OS: {}", build_info::BUILD_OS);
    log::info!("========================================================");
}

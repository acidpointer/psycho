//! Core startup sequence for `psycho_engine_fixes.dll`.
//!
//! The loader calls into `entry.rs`; this module performs the actual engine
//! setup after the DLL is safely outside loader-lock callbacks.

use shadow_rs::shadow;

use crate::{
    config::{DiagnosticsConfig, EngineFixesConfig, MemoryConfig, PerformanceConfig, load_config},
    mods::{
        engine_fixes::install as install_engine_fixes,
        heap_replacer::{
            AllocatorMode, decide_mode, initialize_mimalloc, install_gheap_hooks,
            install_gheap_initialize, install_sheap_hooks, install_sheap_initialize,
        },
        perf::{install_radio_signal_scan_cache, install_rng_hook},
        zlib::install_zlib_hooks,
    },
};
use libpsycho::{
    common::packed_version::PackedVersion, logger::Logger, os::windows::winapi::alloc_console,
};

shadow!(build_info);

const FNV_RUNTIME_VERSION_1_4_0_525: u32 = 0x0400_20D0;

/// Run every core startup step exactly once.
pub(crate) fn initialize() -> anyhow::Result<()> {
    let cfg = load_config();

    initialize_logging(&cfg.diagnostics)?;

    log::info!("[INIT] Engine fixes startup");

    initialize_diagnostics(&cfg.diagnostics)?;
    initialize_memory(&cfg.memory)?;
    install_engine_fix_hooks(&cfg.engine_fixes, &cfg.diagnostics)?;
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
    crate::mods::diagnostics::configure_hitch_profiling(diagnostics.hitch_profiling);
    if diagnostics.hitch_profiling && !diagnostics.debug_log {
        log::warn!(
            "[DIAGNOSTICS] hitch_profiling is enabled but debug_log is disabled; timing summaries will not be written"
        );
    }

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

fn install_engine_fix_hooks(
    engine_fixes: &EngineFixesConfig,
    diagnostics: &DiagnosticsConfig,
) -> anyhow::Result<()> {
    install_engine_fixes(engine_fixes, diagnostics)
}

fn install_runtime_hooks(performance: &PerformanceConfig) -> anyhow::Result<()> {
    if performance.radio_signal_scan_cache {
        install_radio_signal_scan_cache(performance.radio_signal_scan_cache_ttl_ms)?;
    } else {
        log::info!("[RADIO] Periodic nearby-station scan cache disabled by config");
    }

    if performance.rng {
        install_rng_hook()?;
    }

    if performance.zlib {
        install_zlib_hooks(false)?;
    }

    Ok(())
}

fn log_runtime() {
    log::info!(
        "Runtime {}",
        PackedVersion::from_u32(FNV_RUNTIME_VERSION_1_4_0_525)
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

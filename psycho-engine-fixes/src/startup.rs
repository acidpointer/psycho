//! Core startup sequence for `psycho_engine_fixes.dll`.
//!
//! The loader calls into `entry.rs`; this module performs the actual engine
//! setup after the DLL is safely outside loader-lock callbacks.

use shadow_rs::shadow;

use crate::{
    config::{DiagnosticsConfig, EngineFixesConfig, MemoryConfig, PerformanceConfig, load_config},
    mods::{
        engine_fixes::{install as install_engine_fixes, install_display},
        heap_replacer::{
            AllocatorMode, AllocatorPatchPlan, decide_mode, initialize_gheap_runtime,
            initialize_mimalloc, initialize_sheap_runtime, install_gheap_and_sheap_hooks,
            install_sheap_hooks, preflight, prepare_gheap_hooks, prepare_sheap_hooks,
            set_active_mode,
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

    install_display(&cfg.engine_fixes)?;
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
    let requested = decide_mode(memory);
    if requested != AllocatorMode::Disabled && !crate::entry::has_pre_crt_startup_boundary() {
        log::error!(
            "[MEMORY] Allocator mode '{}' rejected: deterministic pre-CRT startup boundary was not reached",
            requested.name(),
        );
        log::error!("[MEMORY] Vanilla allocator retained; other engine fixes will continue");
        set_active_mode(AllocatorMode::Disabled);
        return Ok(());
    }
    let patch_plan = match preflight(requested) {
        Ok(plan) => plan,
        Err(error) => {
            log::error!(
                "[MEMORY] Allocator mode '{}' rejected before activation: {:#}",
                requested.name(),
                error,
            );
            log::error!("[MEMORY] Vanilla allocator retained; other engine fixes will continue");
            set_active_mode(AllocatorMode::Disabled);
            return Ok(());
        }
    };

    let result = match requested {
        AllocatorMode::GheapAndScrapHeap => initialize_gheap_and_scrap_heap(patch_plan),
        AllocatorMode::ScrapHeap => initialize_scrap_heap(),
        AllocatorMode::Disabled => {
            log::info!("[MEMORY] Heap allocator replacement disabled");
            Ok(())
        }
    };
    match result {
        Ok(()) => {
            set_active_mode(requested);
            Ok(())
        }
        Err(error) => {
            log::error!(
                "[MEMORY] Allocator mode '{}' failed during preparation or activation: {:#}",
                requested.name(),
                error,
            );
            log::error!("[MEMORY] Vanilla allocator retained; other engine fixes will continue");
            set_active_mode(AllocatorMode::Disabled);
            Ok(())
        }
    }
}

fn initialize_gheap_and_scrap_heap(patch_plan: AllocatorPatchPlan) -> anyhow::Result<()> {
    // Prove every instruction boundary before reserving allocator VAS or
    // starting the scrap-heap collector thread.
    let realloc_1_ready = prepare_gheap_hooks(patch_plan.hook_gheap_realloc_1)?;
    prepare_sheap_hooks()?;

    // Finish the only fallible allocator-state setup before mimalloc reserves
    // its arena. Mimalloc backs scrap-heap regions; game objects stay in gheap.
    initialize_gheap_runtime()?;
    initialize_mimalloc();
    initialize_sheap_runtime();
    install_gheap_and_sheap_hooks(realloc_1_ready)?;

    Ok(())
}

fn initialize_scrap_heap() -> anyhow::Result<()> {
    prepare_sheap_hooks()?;

    initialize_mimalloc();
    initialize_sheap_runtime();
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

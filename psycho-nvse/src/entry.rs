//! Plugin entry points: DllMain, NVSEPlugin_Query, NVSEPlugin_Load.
//!
//! ## Two-phase initialization
//!
//! **Phase 1 — DllMain (loader lock held):**
//! Minimal setup only: config read, logger registration (deferred), mimalloc
//! config, CRT hooks. NO thread creation, NO disk writes, NO game heap hooks.
//!
//! **Phase 2 — NVSEPlugin_Load (loader lock released):**
//! Logger thread starts, log file opens, game heap hooks installed.
//! Now we have full logging before any allocator rewrites run.

use shadow_rs::shadow;
use std::sync::Once;

use libnvse::plugin::PluginContext;
use libnvse::{NVSEInterfaceFFI, PluginInfoFFI};
use libpsycho::{
    common::exe_version::ExeVersion,
    logger::Logger,
    os::windows::{types::LPVOID, winapi::alloc_console},
};
use windows::{
    Win32::{
        Foundation::HINSTANCE,
        System::SystemServices::{
            DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH,
        },
    },
    core::BOOL,
};

use crate::{
    config::{PsychoConfig, load_config, sync_config},
    mods::{
        memory::{
            configure_mimalloc, install_crt_hooks,
            heap_replacer::{install_game_heap_hooks, start_deferred_threads},
        },
        display::install_display_hooks,
        perf::install_rng_hook,
        zlib::install_zlib_hooks,
    },
    plugininfo,
};

// Collect build info
shadow!(build_info);

// -----------------------------------------------------------------------
// Single initialization guard
// -----------------------------------------------------------------------

static INIT: Once = Once::new();

/// Register the logger with the `log` crate but do NOT spawn the background
/// thread or open the log file. Messages queue in memory until
/// `Logger::start_deferred()` is called in Phase 2.
///
/// NOTE: `alloc_console()` is deferred to Phase 2 — it can load conhost.exe
/// which triggers DLL loading and deadlocks under the Windows loader lock.
fn init_logger_deferred() {
    if let Err(e) = Logger::new()
        .with_file_rotating("./psycho-nvse-latest.log")
        .with_level(log::LevelFilter::Debug)
        .init_deferred()
    {
        eprintln!("psycho-nvse: Failed to initialize logger: {:?}", e);
    }
}

// -----------------------------------------------------------------------
// Phase 1 — Early load (DllMain, loader lock held)
// -----------------------------------------------------------------------
// NO thread creation. NO file writes. NO blocking I/O.
// Game heap hooks are deferred to Phase 2 so logs work before any
// allocator rewrites run.

fn early_load(cfg: &PsychoConfig) {
    configure_mimalloc();

    install_if(cfg.memory.crt_hooks, "CRT hooks", install_crt_hooks);
    install_if(cfg.perf.rng, "RNG replacement", install_rng_hook);
    install_if(
        cfg.display.borderless,
        "Borderless fullscreen",
        install_display_hooks,
    );
}

// -----------------------------------------------------------------------
// Phase 2 — Late load (NVSEPlugin_Load, loader lock released)
// -----------------------------------------------------------------------
// Safe for threads, file I/O, NVSE APIs.
// Game heap hooks are installed here so we have full logging.

fn late_load(nvse_ptr: *const NVSEInterfaceFFI) -> anyhow::Result<()> {
    // --- Deferred startup (threads + file I/O) ---

    // Allocate console window if configured (deferred from DllMain because
    // AllocConsole can load conhost.exe, which deadlocks under loader lock).
    if let Ok(cfg) = crate::config::get_config()
        && cfg.general.console {
            let _ = alloc_console();
        }

    // Start the logger background thread + open the log file.
    // All messages queued during Phase 1 are drained immediately.
    Logger::start_deferred();

    // Write config to disk if schema changed (adds missing fields, prunes stale).
    sync_config();

    // --- Game heap hooks (NOW we have logging to see what happens) ---

    let cfg = crate::config::get_config()?;

    install_if(
        cfg.memory.game_heap_hooks,
        "Game heap hooks",
        install_game_heap_hooks,
    );

    // Start heap monitor thread (watchdog + pressure logging).
    start_deferred_threads();

    // --- NVSE setup ---

    let mut ctx = PluginContext::new(nvse_ptr, plugininfo::PLUGIN_NAME)?;

    if ctx.is_editor() {
        log::info!("Running inside GECK editor -- skipping all game modifications");
        return Ok(());
    }

    crate::nvse_services::init(nvse_ptr);

    // Store console interface globally so command handlers can print
    if let Ok(console) = ctx.low_level().query_console() {
        console.set_global();
    }

    log::info!(
        "xNVSE {}, Runtime {}",
        ctx.nvse_version(),
        ctx.runtime_version()
    );

    // -- Message listener ---------------------------------------------------

    ctx.on_message(|msg| {
        use libnvse::api::messaging::NVSEMessageType;
        if msg.get_type() == NVSEMessageType::DeferredInit {
            crate::nvse_services::set_game_ready();
            log::info!("[NVSE] Game engine ready");
            crate::mods::display::verify_display_resolution();
        }
    })?;

    // -- Console commands ---------------------------------------------------

    // 0x3F00 -- temporary dev range. Must request official allocation
    // from xNVSE team before release: https://geckwiki.com/index.php?title=NVSE_Opcode_Base
    if let Err(e) = ctx.set_opcode_base(0x3F00) {
        log::error!("[FAIL] set_opcode_base: {}", e);
    } else {
        log::info!("[OK] Opcode base set to 0x3F00");
        crate::commands::register(&mut ctx);
    }

    // -- Hooks --------------------------------------------------------------

    if cfg.zlib.enabled {
        install_zlib_hooks(ctx.low_level())?;
        log::info!("[OK] Zlib replacement");
    } else {
        log::warn!("[SKIP] Zlib replacement");
    }

    // PluginContext owns:
    //   - messaging BareFn closures (NVSE holds raw pointers)
    //   - command BareFn trampolines (NVSE holds raw pointers)
    //   - serialization BareFn closures (if any)
    // All must stay alive for the game session. Leak the context.
    // This is the standard pattern for NVSE plugins -- C++ plugins
    // store their interfaces as globals that are never freed.
    std::mem::forget(ctx);

    Ok(())
}

// -----------------------------------------------------------------------
// Helper
// -----------------------------------------------------------------------

fn install_if<F>(enabled: bool, name: &str, f: F)
where
    F: FnOnce() -> anyhow::Result<()>,
{
    if !enabled {
        log::warn!("[SKIP] {}", name);
        return;
    }

    match f() {
        Ok(_) => log::info!("[OK] {}", name),
        Err(err) => log::error!("[FAIL] {}: {:?}", name, err),
    }
}

// -----------------------------------------------------------------------
// FFI exports
// -----------------------------------------------------------------------

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(hmodule: HINSTANCE, reason: u32, _reserved: LPVOID) -> BOOL {
    match reason {
        DLL_PROCESS_ATTACH => {
            // Phase 1: loader lock held — NO threads, NO file writes.
            INIT.call_once(|| {
                let cfg = load_config();
                init_logger_deferred();
                log::info!("Process attach (HMODULE: {:p})", hmodule.0);
                early_load(cfg);
            });
        }
        DLL_PROCESS_DETACH => {
            log::info!("Process detach (HMODULE: {:p})", hmodule.0);
        }
        DLL_THREAD_ATTACH | DLL_THREAD_DETACH => {}
        _ => {
            log::warn!("Unknown DLL reason code {:#x}", reason);
        }
    }

    true.into()
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn NVSEPlugin_Preload() -> BOOL {
    log::debug!("NVSEPlugin_Preload called");
    true.into()
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "C" fn NVSEPlugin_Query(
    nvse: *const NVSEInterfaceFFI,
    info: *mut PluginInfoFFI,
) -> BOOL {
    let nvse = unsafe { &*nvse };
    let info = unsafe { &mut *info };

    let nvse_version = ExeVersion::from_u32(nvse.nvseVersion);
    let runtime_version = ExeVersion::from_u32(nvse.runtimeVersion);

    log::info!(
        "NVSE version: {}, Runtime: {}",
        nvse_version,
        runtime_version
    );

    info.name = plugininfo::PLUGIN_NAME.as_ptr();
    info.version = plugininfo::PLUGIN_VERSION;

    true.into()
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "C" fn NVSEPlugin_Load(nvse: *const NVSEInterfaceFFI) -> BOOL {
    // Phase 2: loader lock released — threads and file I/O are safe.
    match late_load(nvse) {
        Ok(_) => {
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
            true.into()
        }
        Err(err) => {
            log::error!("Plugin load error: {:?}", err);
            false.into()
        }
    }
}

//! Plugin entry points: DllMain, NVSEPlugin_Preload, NVSEPlugin_Query,
//! NVSEPlugin_Load.
//!
//! ## Initialization order
//!
//! **DllMain:** Empty (loader lock held -- nothing safe to do).
//!
//! **NVSEPlugin_Preload (loader lock released):**
//! Config read, logger setup, mimalloc config, slab VAS reservation,
//! heap cache, hook trampoline preparation. Game functions still run
//! through original code -- only trampolines allocated, no JMPs written.
//!
//! **NVSEPlugin_Load (full NVSE available):**
//! Activate all hooks (write JMPs), apply SBM patches, start background
//! threads, NVSE services, console commands.

use shadow_rs::shadow;

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
    config::load_config,
    mods::{
        display::install_display_hooks,
        heap_replacer::{configure_mimalloc, heap_replacer_activate, heap_replacer_initialize},
        perf::install_rng_hook,
        zlib::install_zlib_hooks,
    },
    plugininfo,
};

shadow!(build_info);

// -----------------------------------------------------------------------
// Load -- activate hooks, start threads, NVSE services
// -----------------------------------------------------------------------

fn entrypoint(nvse_ptr: *const NVSEInterfaceFFI) -> anyhow::Result<()> {
    // Start logger background thread + open log file.
    Logger::start_deferred();

    // --- NVSE setup ---

    let mut ctx = PluginContext::new(nvse_ptr, plugininfo::PLUGIN_NAME)?;

    if ctx.is_editor() {
        log::info!("Running inside GECK editor -- skipping all game modifications");
        return Ok(());
    }

    if let Ok(console) = ctx.low_level().query_console() {
        console.set_global();
    }

    log::info!(
        "xNVSE {}, Runtime {}",
        ctx.nvse_version(),
        ctx.runtime_version()
    );

    ctx.on_message(|msg| {
        use libnvse::api::messaging::NVSEMessageType;
        if msg.get_type() == NVSEMessageType::DeferredInit {
            crate::nvse_services::set_game_ready();
            log::info!("[NVSE] Game engine ready - DeferredInit message received!");
            crate::mods::display::verify_display_resolution();
        }
    })?;

    if let Err(e) = ctx.set_opcode_base(0x3F00) {
        log::error!("[FAIL] set_opcode_base: {}", e);
    } else {
        log::info!("[OK] Opcode base set to 0x3F00");
        crate::commands::register(&mut ctx);
    }

    if let Ok(cfg) = crate::config::get_config() {
        if cfg.general.console {
            alloc_console()?;
        }

        if cfg.memory.heap_replacer {
            heap_replacer_activate()?;
        }

        if cfg.perf.rng {
            install_rng_hook()?;
        }

        if cfg.zlib.enabled {
            install_zlib_hooks(ctx.low_level())?;
        }

        if cfg.display.tweaks {
            install_display_hooks()?;
        }
    }

    std::mem::forget(ctx);

    Ok(())
}

// -----------------------------------------------------------------------
// FFI exports
// -----------------------------------------------------------------------

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(_hmodule: HINSTANCE, reason: u32, _reserved: LPVOID) -> BOOL {
    match reason {
        DLL_PROCESS_ATTACH | DLL_PROCESS_DETACH | DLL_THREAD_ATTACH | DLL_THREAD_DETACH => {}
        _ => {}
    }
    true.into()
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn NVSEPlugin_Preload() -> BOOL {
    let cfg = load_config();

    // We check for config value, debug mode is optional
    let log_level: log::LevelFilter = if cfg.logger.debug {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    if let Err(e) = Logger::new()
        .with_file_rotating("./psycho-nvse-latest.log")
        .with_level(log_level)
        .init()
    {
        eprintln!("psycho-nvse: Failed to initialize logger: {:?}", e);
        return false.into();
    }

    log::info!("[PRELOAD] Config loaded, logger ready");

    configure_mimalloc();

    if cfg.memory.heap_replacer {
        match heap_replacer_initialize() {
            Ok(_) => {}
            Err(err) => {
                log::error!("[FAIL] Game heap init: {:?}", err);
            }
        }
    }

    log::info!("[PRELOAD] Infrastructure initialized, trampolines prepared");

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
    match entrypoint(nvse) {
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

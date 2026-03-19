//! Plugin entry points: DllMain, NVSEPlugin_Query, NVSEPlugin_Load.
//!
//! DllMain (early load) installs patches that must be active before the
//! engine initializes: allocator replacement and performance tweaks.
//! NVSEPlugin_Load (late load) handles patches that depend on NVSE
//! infrastructure, such as zlib hooks.

use std::sync::Once;

use libnvse::{NVSEInterfaceFFI, PluginInfoFFI, api::interface::NVSEInterface};
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
    config::{PsychoConfig, load_config},
    mods::{
        memory::{configure_mimalloc, install_crt_hooks, replacer::install_game_heap_hooks},
        perf::{install_rng_hook, set_timer_resolution},
        zlib::install_zlib_hooks,
    },
    plugininfo,
};

// -----------------------------------------------------------------------
// Single initialization guard
// -----------------------------------------------------------------------

static INIT: Once = Once::new();

/// Initialize logger and optionally the console window.
fn init_logger(console: bool) {
    if console {
        let _ = alloc_console();
    }

    if let Err(e) = Logger::new()
        .with_file_rotating("./psycho-nvse-latest.log")
        .with_level(log::LevelFilter::Debug)
        .init()
    {
        // Cannot panic in DllMain — would crash the entire game process.
        // Best effort: write to stderr (visible if console is open).
        eprintln!("psycho-nvse: Failed to initialize logger: {:?}", e);
    }
}

// -----------------------------------------------------------------------
// Early load (DllMain) - patches that must be active before engine init
// -----------------------------------------------------------------------

/// Install all early-load patches. Errors are logged but never propagated
/// (DllMain cannot return errors meaningfully).
fn early_load(cfg: &PsychoConfig) {
    configure_mimalloc();

    install_if(cfg.memory.crt_hooks, "CRT hooks", install_crt_hooks);
    install_if(cfg.memory.game_heap_hooks, "Game heap hooks", install_game_heap_hooks);
    install_if(cfg.perf.timer_resolution, "Timer resolution", set_timer_resolution);
    install_if(cfg.perf.rng, "RNG replacement", install_rng_hook);
}

// -----------------------------------------------------------------------
// Late load (NVSEPlugin_Load) - patches that need NVSE infrastructure
// -----------------------------------------------------------------------

fn late_load(nvse_ptr: *const NVSEInterfaceFFI) -> anyhow::Result<()> {
    let nvse = NVSEInterface::from_raw(nvse_ptr)?;
    let cfg = crate::config::get_config()?;

    if cfg.zlib.enabled {
        install_zlib_hooks(&nvse)?;
        log::info!("[OK] Zlib replacement");
    } else {
        log::warn!("[SKIP] Zlib replacement");
    }

    Ok(())
}

// -----------------------------------------------------------------------
// Helper
// -----------------------------------------------------------------------

/// Run an install function if the config flag is enabled.
/// Logs success/failure/skip uniformly.
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
            INIT.call_once(|| {
                let cfg = load_config();
                init_logger(cfg.general.console);
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

/// # Safety
/// Called by NVSE. Pointers must be valid.
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

    log::info!("NVSE version: {}, Runtime: {}", nvse_version, runtime_version);

    info.name = plugininfo::PLUGIN_NAME.as_ptr();
    info.version = plugininfo::PLUGIN_VERSION;

    true.into()
}

/// # Safety
/// Called by NVSE. Pointer must be valid.
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "C" fn NVSEPlugin_Load(nvse: *const NVSEInterfaceFFI) -> BOOL {
    match late_load(nvse) {
        Ok(_) => log::info!("Plugin loaded successfully"),
        Err(err) => log::error!("Plugin load error: {:?}", err),
    }

    true.into()
}

//! Plugin entry points: DllMain, NVSEPlugin_Query, NVSEPlugin_Load.
//!
//! DllMain (early load) installs patches that must be active before the
//! engine initializes: allocator replacement and performance tweaks.
//! NVSEPlugin_Load (late load) handles patches that depend on NVSE
//! infrastructure, such as zlib hooks.

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
    config::{PsychoConfig, load_config},
    mods::{
        memory::{configure_mimalloc, install_crt_hooks, replacer::install_game_heap_hooks},
        perf::install_rng_hook,
        zlib::install_zlib_hooks,
    },
    plugininfo,
};

// -----------------------------------------------------------------------
// Single initialization guard
// -----------------------------------------------------------------------

static INIT: Once = Once::new();

fn init_logger(console: bool) {
    if console {
        let _ = alloc_console();
    }

    if let Err(e) = Logger::new()
        .with_file_rotating("./psycho-nvse-latest.log")
        .with_level(log::LevelFilter::Debug)
        .init()
    {
        eprintln!("psycho-nvse: Failed to initialize logger: {:?}", e);
    }
}

// -----------------------------------------------------------------------
// Early load (DllMain) -- patches before engine init
// -----------------------------------------------------------------------

fn early_load(cfg: &PsychoConfig) {
    configure_mimalloc();

    install_if(cfg.memory.crt_hooks, "CRT hooks", install_crt_hooks);
    install_if(
        cfg.memory.game_heap_hooks,
        "Game heap hooks",
        install_game_heap_hooks,
    );
    install_if(cfg.perf.rng, "RNG replacement", install_rng_hook);
}

// -----------------------------------------------------------------------
// Late load (NVSEPlugin_Load) -- patches that need NVSE
// -----------------------------------------------------------------------

fn late_load(nvse_ptr: *const NVSEInterfaceFFI) -> anyhow::Result<()> {
    let ctx = PluginContext::new(nvse_ptr, plugininfo::PLUGIN_NAME)?;

    if ctx.is_editor() {
        log::info!("Running inside GECK editor -- skipping all game modifications");
        return Ok(());
    }

    // Initialize global services so subsystems can access console/UI.
    // We store only the raw pointer -- no NVSEInterface reconstruction
    // during pressure callbacks (that would call GetPluginHandle again).
    crate::nvse_services::init(nvse_ptr);

    log::info!(
        "xNVSE {}, Runtime {}",
        ctx.nvse_version(),
        ctx.runtime_version()
    );

    let cfg = crate::config::get_config()?;

    if cfg.zlib.enabled {
        install_zlib_hooks(ctx.low_level())?;
        log::info!("[OK] Zlib replacement");
    } else {
        log::warn!("[SKIP] Zlib replacement");
    }

    // Register message handler AFTER all hooks are installed.
    register_nvse_listener(nvse_ptr);

    Ok(())
}

/// Register NVSE message listener using a leaked BareFn.
///
/// Separated from late_load so the NVSEInterface (and its messaging
/// sub-interface) can be dropped cleanly without needing forget().
fn register_nvse_listener(nvse_ptr: *const NVSEInterfaceFFI) {
    let mut nvse = match libnvse::api::interface::NVSEInterface::from_raw(nvse_ptr) {
        Ok(n) => n,
        Err(e) => {
            log::error!("Failed to create NVSEInterface for listener: {}", e);
            return;
        }
    };

    let result = nvse.messaging_interface_mut().register_listener("NVSE", |msg| {
        use libnvse::api::messaging::NVSEMessageType;
        if msg.get_type() == NVSEMessageType::DeferredInit {
            crate::nvse_services::set_game_ready();
            log::info!("[NVSE] Game engine ready");
        }
    });

    match result {
        Ok(_) => log::info!("[OK] NVSE message listener"),
        Err(e) => log::error!("[FAIL] NVSE message listener: {}", e),
    }

    // nvse is dropped here. The NVSEMessagingInterface inside it holds
    // the BareFn in its HashMap. When dropped, the BareFn is freed.
    // This means the listener callback becomes a dangling pointer!
    //
    // To keep the closure alive, we leak the entire NVSEInterface.
    // This is the same pattern used by every C++ NVSE plugin (they
    // store g_messagingInterface as a global that's never freed).
    std::mem::forget(nvse);
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
    match late_load(nvse) {
        Ok(_) => log::info!("Plugin loaded successfully"),
        Err(err) => log::error!("Plugin load error: {:?}", err),
    }

    true.into()
}

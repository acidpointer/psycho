use std::sync::Once;

use libnvse::{NVSEInterface, PluginInfo};
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

use crate::{mods::memory::{install_crt_hooks, install_crt_inline_hooks}, plugininfo};

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(hmodule: HINSTANCE, reason: u32, _reserved: LPVOID) -> BOOL {
    static LOGGER_INIT: Once = Once::new();

    static CRT_INLINE_HOOKS_INIT: Once = Once::new();
    static CRT_IAT_HOOKS_INIT: Once = Once::new();

    LOGGER_INIT.call_once(|| {
        // Allocate a console window for the game process
        let _ = alloc_console();

        // Initialize logger with both console and file output
        Logger::new()
            .with_file_rotating("./psycho-nvse-latest.log")
            .with_level(log::LevelFilter::Debug)
            .init()
            .expect("Failed to initialize logger");
    });

    let result = match reason {
        DLL_PROCESS_ATTACH => {
            log::info!("Process attach - initializing");

            log::info!("(DllMain) HMODULE: {:p}", hmodule.0);

            CRT_IAT_HOOKS_INIT.call_once(|| {
                match install_crt_hooks() {
                    Ok(_) => {
                        log::info!("IAT CRT hooks installed");
                    },

                    Err(err) => {
                        log::error!("IAT CRT hooks install error: {:?}", err);
                    }
                }
            });

            // CRT Inline hooks must be installed as earliest as possible,
            // otherwise we will get game crash
            CRT_INLINE_HOOKS_INIT.call_once(|| {
                match install_crt_inline_hooks() {
                    Ok(_) => {
                        log::info!("Inline CRT hooks installed");
                    },

                    Err(err) => {
                        log::error!("Inline CRT hooks install error: {:?}", err);
                    },
                }
            });


            true
        }
        DLL_PROCESS_DETACH => {
            log::info!("Process detach (module: {:p})", hmodule.0);
            true
        }
        DLL_THREAD_ATTACH => true,
        DLL_THREAD_DETACH => true,
        _ => {
            log::warn!("Unknown DLL reason code {:#x}", reason);
            true
        }
    };

    result.into()
}

/// Preload function for NVSE
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn NVSEPlugin_Preload() -> BOOL {
    log::debug!("NVSEPlugin_Preload called!");

    true.into()
}

/// NVSEPlugin_Query
///
/// # Safety
/// Unsafe, caller must be carefull
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "C" fn NVSEPlugin_Query(
    nvse: *const NVSEInterface,
    info: *mut PluginInfo,
) -> BOOL {
    let nvse = unsafe { &*nvse };
    let info = unsafe { &mut *info };

    let nvse_version = ExeVersion::from_u32(nvse.nvseVersion);
    let runtime_version = ExeVersion::from_u32(nvse.runtimeVersion);

    log::info!("NVSEPlugin_Query called! NVSEInterface address: {:p}", nvse);
    log::info!("NVSE version: {}", nvse_version);
    log::info!("Runtime version: {}", runtime_version);

    info.name = plugininfo::PLUGIN_NAME.as_ptr();
    info.version = plugininfo::PLUGIN_VERSION;

    true.into()
}

/// # Safety
/// Unsafe, caller must be carefull
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "C" fn NVSEPlugin_Load(nvse: *const NVSEInterface) -> BOOL {
    log::info!("NVSEPlugin_Load called! NVSEInterface address: {:p}", nvse);

    let nvse = unsafe { &*nvse };

    // Business logic starts here

    match start() {
        Ok(_) => {
            log::warn!("Plugin loaded without errors!")
        }
        Err(err) => {
            log::error!("Error in plugin load: {:?}", err);
        }
    }

    true.into()
}

/// Main function which executes when plugin ready
/// 
/// This function must return result.
/// 
/// # Safety
/// Developer responsible to make this function free of hidded panics,
/// or silent errors. Result MUST be propagated.
/// Usage of .expect or .unwrap strongly not recommended!
fn start() -> anyhow::Result<()> {
    log::info!("start() called, plugin fully loaded and ready!");
    
    Ok(())
}

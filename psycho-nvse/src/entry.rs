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
    mods::{
        memory::{configure_mimalloc, install_crt_hooks, replacer::install_game_heap_hooks},
        perf::{
            boost_main_thread_priority, install_critical_section_hooks, install_sleep_patches,
            patch_deferred_task_budget, set_timer_resolution,
        },
        stability::install_null_deref_guards,
        zlib::install_zlib_hooks,
    },
    plugininfo,
};

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(hmodule: HINSTANCE, reason: u32, _reserved: LPVOID) -> BOOL {
    static LOGGER_INIT: Once = Once::new();

    static CRT_IAT_HOOKS_INIT: Once = Once::new();

    static CS_HOOK_INIT: Once = Once::new();

    static HEAP_PATCH_INIT: Once = Once::new();

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

            configure_mimalloc();

            CRT_IAT_HOOKS_INIT.call_once(|| match install_crt_hooks() {
                Ok(_) => {
                    log::info!("IAT CRT hooks installed");
                }

                Err(err) => {
                    log::error!("IAT CRT hooks install error: {:?}", err);
                }
            });

            // Stability: null pointer dereference guards
            match install_null_deref_guards() {
                Ok(_) => {
                    log::info!("Null deref guards installed");
                }
                Err(err) => {
                    log::error!("Null deref guards error: {:?}", err);
                }
            }

            // Set timer resolution to 1ms - critical for Sleep patches and frame pacing
            match set_timer_resolution() {
                Ok(_) => {
                    log::info!("Timer resolution set to 1ms");
                }
                Err(err) => {
                    log::error!("Timer resolution error: {:?}", err);
                }
            }

            // Boost main thread priority to reduce scheduler jitter
            match boost_main_thread_priority() {
                Ok(_) => {
                    log::info!("Main thread priority boosted");
                }
                Err(err) => {
                    log::error!("Thread priority boost error: {:?}", err);
                }
            }

            CS_HOOK_INIT.call_once(|| match install_critical_section_hooks() {
                Ok(_) => {
                    log::info!("Critical section spin count hooks installed");
                }
                Err(err) => {
                    log::error!("Critical section hooks install error: {:?}", err);
                }
            });

            // Sleep duration patches - reduce I/O polling from 10-50ms to 1ms
            match install_sleep_patches() {
                Ok(_) => {
                    log::info!("Sleep patches installed");
                }
                Err(err) => {
                    log::error!("Sleep patches install error: {:?}", err);
                }
            }

            // Deferred task budget - reduce 1000ms overflow budget to 100ms
            match patch_deferred_task_budget() {
                Ok(_) => {
                    log::info!("Deferred task budget patched");
                }
                Err(err) => {
                    log::error!("Deferred task budget patch error: {:?}", err);
                }
            }

            HEAP_PATCH_INIT.call_once(|| match install_game_heap_hooks() {
                Ok(_) => {
                    log::info!("Game heap patch ready!");
                }

                Err(err) => {
                    log::error!("Game heap patch install error: {:?}", err);
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
    nvse: *const NVSEInterfaceFFI,
    info: *mut PluginInfoFFI,
) -> BOOL {
    let nvse = unsafe { &*nvse };
    let info = unsafe { &mut *info };

    log::info!("NVSEPlugin_Query called! NVSEInterface address: {:p}", nvse);

    let nvse_version = ExeVersion::from_u32(nvse.nvseVersion);
    let runtime_version = ExeVersion::from_u32(nvse.runtimeVersion);

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
pub unsafe extern "C" fn NVSEPlugin_Load(nvse: *const NVSEInterfaceFFI) -> BOOL {
    log::info!("NVSEPlugin_Load called! NVSEInterface address: {:p}", nvse);

    // Business logic starts here
    match start(nvse) {
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
fn start(nvse_ptr: *const NVSEInterfaceFFI) -> anyhow::Result<()> {
    log::info!("start() called!");

    let nvse_interface = NVSEInterface::from_raw(nvse_ptr)?;

    install_zlib_hooks(&nvse_interface)?;

    Ok(())
}

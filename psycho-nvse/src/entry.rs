use std::sync::Once;

use libnvse::{
    NVSEInterface, NVSEMessagingInterface, NVSEMessagingInterface_Message, PluginInfo,
    api::{
        message_box::show_message_box,
        messaging::{NVSEMessage, NVSEMessageType},
    },
    kInterface_Messaging,
};
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
        memory::{install_crt_hooks, install_crt_inline_hooks, install_game_heap_hooks},
        zlib::install_zlib_hooks,
    },
    plugininfo,
};

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(hmodule: HINSTANCE, reason: u32, _reserved: LPVOID) -> BOOL {
    static LOGGER_INIT: Once = Once::new();

    static CRT_INLINE_HOOKS_INIT: Once = Once::new();
    static CRT_IAT_HOOKS_INIT: Once = Once::new();

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

            CRT_IAT_HOOKS_INIT.call_once(|| match install_crt_hooks() {
                Ok(_) => {
                    log::info!("IAT CRT hooks installed");
                }

                Err(err) => {
                    log::error!("IAT CRT hooks install error: {:?}", err);
                }
            });

            // CRT Inline hooks must be installed as earliest as possible,
            // otherwise we will get game crash
            CRT_INLINE_HOOKS_INIT.call_once(|| match install_crt_inline_hooks() {
                Ok(_) => {
                    log::info!("Inline CRT hooks installed");
                }

                Err(err) => {
                    log::error!("Inline CRT hooks install error: {:?}", err);
                }
            });

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
    nvse: *const NVSEInterface,
    info: *mut PluginInfo,
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
pub unsafe extern "C" fn NVSEPlugin_Load(nvse: *const NVSEInterface) -> BOOL {
    log::info!("NVSEPlugin_Load called! NVSEInterface address: {:p}", nvse);

    let nvse = unsafe { &*nvse };

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

extern "C" fn msg_cb(msg: *mut NVSEMessagingInterface_Message) {
    let msg = NVSEMessage::from(unsafe { &*msg });

    let msg_type = msg.get_type();

    if msg_type == NVSEMessageType::MainGameLoop
        || msg_type == NVSEMessageType::OnFramePresent
        || msg_type == NVSEMessageType::ScriptCompile
        || msg_type == NVSEMessageType::EventListDestroyed
    {
        return;
    }

    log::info!("Message received: {}", msg.get_type());

    if msg.get_type() == NVSEMessageType::DeferredInit {
        match show_message_box("psycho-nvse loaded! Have FUN!", "YUP") {
            Ok(_) => {}
            Err(err) => {
                log::error!("show_message_box error: {:?}", err);
            }
        }
    }
}

/// Main function which executes when plugin ready
///
/// This function must return result.
///
/// # Safety
/// Developer responsible to make this function free of hidded panics,
/// or silent errors. Result MUST be propagated.
/// Usage of .expect or .unwrap strongly not recommended!
fn start(nvse: &NVSEInterface) -> anyhow::Result<()> {
    log::info!("start() called!");

    install_zlib_hooks(nvse)?;

    if let Some(query_interface_fn) = nvse.QueryInterface {
        let messaging_interface = unsafe { query_interface_fn(kInterface_Messaging as u32) }
            as *mut NVSEMessagingInterface;

        let messaging_interface = unsafe { &*messaging_interface };

        if let Some(register_listener_fn) = messaging_interface.RegisterListener
            && let Some(get_plugin_handle_fn) = nvse.GetPluginHandle
        {
            let plugin_handle = unsafe { get_plugin_handle_fn() };

            unsafe { register_listener_fn(plugin_handle, c"NVSE".as_ptr(), Some(msg_cb)) };
        }
    }

    Ok(())
}

#![allow(non_snake_case)]

//! xNVSE entrypoint for Oh My Vegas graphics.

use libnvse::api::messaging::{NVSEMessage, NVSEMessageType};
use libnvse::plugin::PluginContext;
use libnvse::{NVSEInterfaceFFI, PluginInfoFFI};
use windows::core::BOOL;

const PLUGIN_INFO_VERSION: u32 = 1;

/// xNVSE preload callback.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NVSEPlugin_Preload() -> BOOL {
    true.into()
}

/// xNVSE metadata query callback.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NVSEPlugin_Query(
    nvse: *const NVSEInterfaceFFI,
    info: *mut PluginInfoFFI,
) -> BOOL {
    if unsafe { nvse.as_ref() }.is_none() {
        return false.into();
    }
    let Some(info) = (unsafe { info.as_mut() }) else {
        return false.into();
    };

    info.infoVersion = PLUGIN_INFO_VERSION;
    info.name = crate::plugininfo::PLUGIN_NAME.as_ptr();
    info.version = crate::plugininfo::PLUGIN_VERSION;

    true.into()
}

/// xNVSE load callback.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NVSEPlugin_Load(nvse: *const NVSEInterfaceFFI) -> BOOL {
    match plugin_load(nvse) {
        Ok(()) => true.into(),
        Err(err) => {
            eprintln!("omv: Failed to initialize xNVSE plugin: {err:?}");
            false.into()
        }
    }
}

fn plugin_load(nvse: *const NVSEInterfaceFFI) -> anyhow::Result<()> {
    if unsafe { nvse.as_ref() }.is_none() {
        anyhow::bail!("NVSE interface pointer is NULL");
    }

    crate::startup::initialize_for_nvse()?;

    let mut ctx = PluginContext::new(nvse, crate::plugininfo::PLUGIN_NAME)?;
    log::info!(
        "[XNVSE] Loaded as '{}', xNVSE={}, runtime={}",
        crate::plugininfo::PLUGIN_NAME.to_string_lossy(),
        ctx.nvse_version(),
        ctx.runtime_version(),
    );

    ctx.on_message(handle_message)?;

    // PluginContext owns callback thunks passed to xNVSE. Dropping it after
    // Load would leave xNVSE with stale pointers.
    std::mem::forget(ctx);

    Ok(())
}

fn handle_message(msg: &NVSEMessage) {
    match msg.get_type() {
        NVSEMessageType::PostLoad => crate::startup::observe_post_load(),
        NVSEMessageType::DeferredInit => {
            if let Err(err) = crate::startup::install_deferred_hooks() {
                log::error!("[XNVSE] Deferred graphics hook install failed: {err:#}");
            }
        }
        _ => {}
    }
}

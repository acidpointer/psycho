#![allow(non_snake_case)]

//! xNVSE adapter for `psycho_engine_fixes.dll`.
//!
//! This DLL exists only because console commands and xNVSE messages must be
//! registered from an xNVSE plugin. Core engine patches are owned by
//! `psycho_engine_fixes.dll`, loaded earlier by `psycho-loader`.

mod commands;
mod engine_fixes;
mod events;
mod plugininfo;

use libnvse::plugin::PluginContext;
use libnvse::{NVSEInterfaceFFI, PluginInfoFFI};
use windows::core::BOOL;

const PLUGIN_INFO_VERSION: u32 = 1;

// The previous 0x3F00 range collides with common graphics plugins and xNVSE
// silently overwrites command table entries. Keep this high until we get an
// official assigned range.
const OPCODE_BASE: u32 = 0x7F00;

/// xNVSE preload callback.
///
/// The helper has no preload work. Returning true lets xNVSE continue loading
/// the plugin and keeps core setup owned by `psycho_engine_fixes.dll`.
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
    info.name = plugininfo::PLUGIN_NAME.as_ptr();
    info.version = plugininfo::PLUGIN_VERSION;

    true.into()
}

/// xNVSE load callback.
///
/// This registers helper services only. It must never call `LoadLibrary` or run
/// any core engine-fix initialization.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NVSEPlugin_Load(nvse: *const NVSEInterfaceFFI) -> BOOL {
    match helper_load(nvse) {
        Ok(()) => true.into(),
        Err(err) => {
            log::error!("[HELPER] Load failed: {:?}", err);
            false.into()
        }
    }
}

fn helper_load(nvse: *const NVSEInterfaceFFI) -> anyhow::Result<()> {
    if unsafe { nvse.as_ref() }.is_none() {
        anyhow::bail!("NVSE interface pointer is NULL");
    }

    let mut ctx = PluginContext::new(nvse, plugininfo::PLUGIN_NAME)?;

    // CommandContext::print uses libnvse's global console pointer. Store it
    // once during Load so command handlers can print without owning PluginContext.
    if let Ok(console) = ctx.low_level().query_console() {
        console.set_global();
    }

    // The listener owns a static function pointer through PluginContext.
    // Register it before commands, matching the last stable helper shape.
    ctx.on_message(events::forward_to_engine_fixes)?;

    if let Err(err) = ctx.set_opcode_base(OPCODE_BASE) {
        log::error!("[HELPER] Opcode base 0x{OPCODE_BASE:X} unavailable: {err}");
    } else {
        commands::register(&mut ctx);
    }

    // PluginContext owns the closure thunks and command backing storage passed
    // to xNVSE. Dropping it after Load would leave xNVSE with stale pointers.
    std::mem::forget(ctx);

    Ok(())
}
